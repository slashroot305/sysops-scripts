#!/usr/bin/env python3
"""
Agent Health Dashboard
Syncs Fleet agent status to Elasticsearch and creates a Kibana dashboard.
Designed to run externally via GitHub Actions on a 10-minute schedule.

Usage:
  python create_agent_health_dashboard.py               # sync + dashboard
  python create_agent_health_dashboard.py --sync-only   # agents only (scheduled)
  python create_agent_health_dashboard.py --dashboard-only  # dashboard only (manual)
"""

import os, json, uuid, sys, io
import requests
from elasticsearch import Elasticsearch
from datetime import datetime, timezone

# ── CONFIG (all from environment / GitHub Secrets) ────────────
KIBANA_URL = os.environ.get("KIBANA_URL", "https://my-security-project-aac892.kb.us-east-2.aws.elastic.cloud")
ES_URL     = os.environ.get("ES_URL",     "https://my-security-project-aac892.es.us-east-2.aws.elastic.cloud")
API_KEY    = os.environ["ELASTIC_CLOUD_API_KEY_CLI"]
HEADERS    = {"Authorization": f"ApiKey {API_KEY}", "kbn-xsrf": "true"}

INDEX   = "fleet-agents-health"
DASH_ID = "2c0a3d73-d7e6-4841-8731-437a14471cf1"


# ── 1. SYNC AGENTS ────────────────────────────────────────────
def sync_agents():
    es = Elasticsearch(ES_URL, api_key=API_KEY)

    r = requests.get(
        f"{KIBANA_URL}/api/fleet/agents?perPage=100&showInactive=true",
        headers=HEADERS, timeout=15
    )
    r.raise_for_status()
    agents = r.json().get("items", [])

    if not es.indices.exists(index=INDEX):
        es.indices.create(index=INDEX, mappings={"properties": {
            "hostname":       {"type": "keyword"},
            "os":             {"type": "keyword"},
            "status":         {"type": "keyword"},
            "checkin_status": {"type": "keyword"},
            "agent_version":  {"type": "keyword"},
            "policy_id":      {"type": "keyword"},
            "last_checkin":   {"type": "date"},
            "enrolled_at":    {"type": "date"},
            "active":         {"type": "boolean"},
            "snapshot_time":  {"type": "date"}
        }})
        print(f"Created index: {INDEX}")

    now = datetime.now(timezone.utc).isoformat()
    for a in agents:
        es.index(index=INDEX, id=a["id"], document={
            "hostname":       a.get("local_metadata", {}).get("host", {}).get("hostname", "unknown"),
            "os":             a.get("local_metadata", {}).get("os", {}).get("name", "unknown"),
            "status":         a.get("status", "unknown"),
            "checkin_status": a.get("last_checkin_status", "unknown"),
            "agent_version":  a.get("agent", {}).get("version", "unknown"),
            "policy_id":      a.get("policy_id", ""),
            "last_checkin":   a.get("last_checkin"),
            "enrolled_at":    a.get("enrolled_at"),
            "active":         a.get("active", False),
            "snapshot_time":  now
        })

    es.indices.refresh(index=INDEX)
    online  = sum(1 for a in agents if a.get("status") == "online")
    offline = sum(1 for a in agents if a.get("status") == "offline")
    print(f"Synced {len(agents)} agents | Online: {online} | Offline: {offline} | {now}")


# ── 2. BUILD DASHBOARD ────────────────────────────────────────
def build_dashboard():
    metric_id = str(uuid.uuid4())
    pie_id    = str(uuid.uuid4())
    table_id  = str(uuid.uuid4())

    def vega_obj(obj_id, title, spec):
        return {
            "type": "visualization",
            "id": obj_id,
            "attributes": {
                "title": title,
                "visState": json.dumps({
                    "type": "vega",
                    "aggs": [],
                    "params": {"spec": json.dumps(spec, indent=2)}
                }),
                "uiStateJSON": "{}",
                "description": "",
                "version": 1,
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "query": {"language": "kuery", "query": ""},
                        "filter": []
                    })
                }
            },
            "coreMigrationVersion": "9.0.0",
            "references": []
        }

    metric_spec = {
        "$schema": "https://vega.github.io/schema/vega/v5.json",
        "padding": 5,
        "data": [{
            "name": "online",
            "url": {
                "index": INDEX,
                "body": {
                    "size": 0,
                    "query": {"term": {"status": "online"}},
                    "aggs": {"n": {"value_count": {"field": "hostname"}}}
                }
            },
            "format": {"property": "aggregations.n"}
        }],
        "marks": [
            {
                "type": "text", "from": {"data": "online"},
                "encode": {"update": {
                    "text": {"field": "value"},
                    "x": {"signal": "width / 2"},
                    "y": {"signal": "height / 2 - 12"},
                    "fontSize": {"value": 64},
                    "fontWeight": {"value": "bold"},
                    "align": {"value": "center"},
                    "baseline": {"value": "middle"},
                    "fill": {"value": "#007871"}
                }}
            },
            {
                "type": "text",
                "encode": {"enter": {
                    "text": {"value": "agents online"},
                    "x": {"signal": "width / 2"},
                    "y": {"signal": "height / 2 + 40"},
                    "fontSize": {"value": 15},
                    "align": {"value": "center"},
                    "fill": {"value": "#69707D"}
                }}
            }
        ]
    }

    pie_spec = {
        "$schema": "https://vega.github.io/schema/vega/v5.json",
        "padding": 5,
        "data": [
            {
                "name": "raw",
                "url": {
                    "index": INDEX,
                    "body": {"size": 0, "aggs": {"by_status": {"terms": {"field": "status", "size": 10}}}}
                },
                "format": {"property": "aggregations.by_status.buckets"}
            },
            {
                "name": "pie", "source": "raw",
                "transform": [{"type": "pie", "field": "doc_count"}]
            }
        ],
        "scales": [{
            "name": "color", "type": "ordinal",
            "domain": ["online", "offline", "degraded"],
            "range": ["#007871", "#BD271E", "#F5A700"]
        }],
        "legends": [{"fill": "color", "title": "Status", "orient": "bottom", "labelFontSize": 14, "titleFontSize": 14, "direction": "horizontal"}],
        "marks": [
            {
                "type": "arc", "from": {"data": "pie"},
                "encode": {"enter": {
                    "x": {"signal": "width / 2"},
                    "y": {"signal": "height / 2"},
                    "startAngle": {"field": "startAngle"},
                    "endAngle": {"field": "endAngle"},
                    "innerRadius": {"signal": "min(width,height) / 4"},
                    "outerRadius": {"signal": "min(width,height) / 2.8"},
                    "fill": {"scale": "color", "field": "key"},
                    "stroke": {"value": "#fff"},
                    "strokeWidth": {"value": 2}
                }}
            },
            {
                "type": "text", "from": {"data": "pie"},
                "encode": {"enter": {
                    "x": {"signal": "width / 2"},
                    "y": {"signal": "height / 2"},
                    "radius": {"signal": "min(width,height) / 2.8 + 16"},
                    "theta": {"signal": "(datum.startAngle + datum.endAngle) / 2"},
                    "text": {"signal": "datum.key + ' (' + datum.doc_count + ')'"},
                    "align": {"value": "center"},
                    "baseline": {"value": "middle"},
                    "fontSize": {"value": 13},
                    "fontWeight": {"value": "bold"},
                    "fill": {"value": "#343741"}
                }}
            }
        ]
    }

    table_spec = {
        "$schema": "https://vega.github.io/schema/vega/v5.json",
        "padding": 5,
        "data": [{
            "name": "agents",
            "url": {
                "index": INDEX,
                "body": {
                    "size": 50,
                    "_source": ["hostname", "status", "agent_version", "last_checkin", "os"],
                    "sort": [{"status": {"order": "asc"}}, {"hostname": {"order": "asc"}}]
                }
            },
            "format": {"property": "hits.hits"},
            "transform": [
                {"type": "formula", "as": "hostname",  "expr": "datum._source.hostname"},
                {"type": "formula", "as": "status",    "expr": "datum._source.status"},
                {"type": "formula", "as": "version",   "expr": "datum._source.agent_version"},
                {"type": "formula", "as": "os",        "expr": "datum._source.os"},
                {"type": "formula", "as": "checkin",   "expr": "slice(datum._source.last_checkin, 0, 19)"},
                {"type": "window",  "ops": ["row_number"], "as": ["rn"]},
                {"type": "formula", "as": "y",         "expr": "datum.rn * 30 + 34"}
            ]
        }],
        "signals": [{"name": "height", "update": "length(data('agents')) * 30 + 54"}],
        "scales": [{
            "name": "sc", "type": "ordinal",
            "domain": ["online", "offline", "degraded"],
            "range": ["#007871", "#BD271E", "#F5A700"]
        }],
        "marks": [
            {"type": "rule", "encode": {"enter": {"x": {"value": 0}, "x2": {"signal": "width"}, "y": {"value": 22}, "stroke": {"value": "#D3DAE6"}, "strokeWidth": {"value": 1}}}},
            {"type": "text", "encode": {"enter": {"x": {"value": 0},   "y": {"value": 14}, "text": {"value": "HOSTNAME"},      "fontWeight": {"value": "bold"}, "fill": {"value": "#FFFFFF"}, "fontSize": {"value": 13}}}},
            {"type": "text", "encode": {"enter": {"x": {"value": 200}, "y": {"value": 14}, "text": {"value": "STATUS"},        "fontWeight": {"value": "bold"}, "fill": {"value": "#343741"}, "fontSize": {"value": 13}}}},
            {"type": "text", "encode": {"enter": {"x": {"value": 300}, "y": {"value": 14}, "text": {"value": "OS"},            "fontWeight": {"value": "bold"}, "fill": {"value": "#FFFFFF"}, "fontSize": {"value": 13}}}},
            {"type": "text", "encode": {"enter": {"x": {"value": 400}, "y": {"value": 14}, "text": {"value": "VERSION"},       "fontWeight": {"value": "bold"}, "fill": {"value": "#FFFFFF"}, "fontSize": {"value": 13}}}},
            {"type": "text", "encode": {"enter": {"x": {"value": 480}, "y": {"value": 14}, "text": {"value": "LAST CHECK-IN"}, "fontWeight": {"value": "bold"}, "fill": {"value": "#FFFFFF"}, "fontSize": {"value": 13}}}},
            {"type": "text", "from": {"data": "agents"}, "encode": {"enter": {"x": {"value": 0},   "y": {"field": "y"}, "text": {"field": "hostname"}, "fill": {"value": "#FFFFFF"},                "fontSize": {"value": 13}, "limit": {"value": 195}}}},
            {"type": "text", "from": {"data": "agents"}, "encode": {"enter": {"x": {"value": 200}, "y": {"field": "y"}, "text": {"field": "status"},   "fill": {"scale": "sc", "field": "status"}, "fontSize": {"value": 13}, "fontWeight": {"value": "bold"}}}},
            {"type": "text", "from": {"data": "agents"}, "encode": {"enter": {"x": {"value": 300}, "y": {"field": "y"}, "text": {"field": "os"},       "fill": {"value": "#FFFFFF"},                "fontSize": {"value": 13}, "limit": {"value": 95}}}},
            {"type": "text", "from": {"data": "agents"}, "encode": {"enter": {"x": {"value": 400}, "y": {"field": "y"}, "text": {"field": "version"},  "fill": {"value": "#FFFFFF"},                "fontSize": {"value": 13}}}},
            {"type": "text", "from": {"data": "agents"}, "encode": {"enter": {"x": {"value": 480}, "y": {"field": "y"}, "text": {"field": "checkin"},  "fill": {"value": "#FFFFFF"},                "fontSize": {"value": 13}}}}
        ]
    }

    panels = [
        {"type": "visualization", "gridData": {"x": 0,  "y": 0,  "w": 8,  "h": 12, "i": "p1"}, "panelIndex": "p1", "embeddableConfig": {"enhancements": {}}, "panelRefName": "panel_0"},
        {"type": "visualization", "gridData": {"x": 8,  "y": 0,  "w": 16, "h": 12, "i": "p2"}, "panelIndex": "p2", "embeddableConfig": {"enhancements": {}}, "panelRefName": "panel_1"},
        {"type": "visualization", "gridData": {"x": 0,  "y": 12, "w": 24, "h": 22, "i": "p3"}, "panelIndex": "p3", "embeddableConfig": {"enhancements": {}}, "panelRefName": "panel_2"},
    ]

    objects = [
        vega_obj(metric_id, "Online Agents",             metric_spec),
        vega_obj(pie_id,    "Agent Status Distribution", pie_spec),
        vega_obj(table_id,  "Agent Details",             table_spec),
        {
            "type": "dashboard",
            "id": DASH_ID,
            "coreMigrationVersion": "9.0.0",
            "attributes": {
                "title": "Agent Health Overview",
                "description": "Fleet agent health: online count, status distribution, and per-agent details",
                "panelsJSON": json.dumps(panels),
                "optionsJSON": json.dumps({"useMargins": True, "syncColors": False, "hidePanelTitles": False}),
                "timeRestore": False,
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({"query": {"language": "kuery", "query": ""}, "filter": []})
                }
            },
            "references": [
                {"type": "visualization", "id": metric_id, "name": "panel_0"},
                {"type": "visualization", "id": pie_id,    "name": "panel_1"},
                {"type": "visualization", "id": table_id,  "name": "panel_2"}
            ]
        }
    ]

    ndjson = "\n".join(json.dumps(o) for o in objects)
    r = requests.post(
        f"{KIBANA_URL}/api/saved_objects/_import?overwrite=true",
        headers={k: v for k, v in HEADERS.items() if k != "Content-Type"},
        files={"file": ("export.ndjson", io.BytesIO(ndjson.encode()), "application/ndjson")},
        timeout=30
    )

    resp = r.json()
    if r.status_code == 200 and resp.get("success"):
        print(f"Dashboard import: {resp.get('successCount')}/{len(objects)} objects created")
        print(f"URL: {KIBANA_URL}/app/dashboards#/view/{DASH_ID}")
    else:
        print(f"Dashboard import failed [{r.status_code}]: {json.dumps(resp, indent=2)}")
        sys.exit(1)


# ── MAIN ──────────────────────────────────────────────────────
if __name__ == "__main__":
    args = sys.argv[1:]
    sync_only      = "--sync-only"      in args
    dashboard_only = "--dashboard-only" in args

    if dashboard_only:
        build_dashboard()
    elif sync_only:
        sync_agents()
    else:
        sync_agents()
        build_dashboard()
