import os, json, uuid, requests, io
from elasticsearch import Elasticsearch
from datetime import datetime, timezone

KIBANA_URL = "https://my-security-project-aac892.kb.us-east-2.aws.elastic.cloud"
ES_URL     = "https://my-security-project-aac892.es.us-east-2.aws.elastic.cloud"
HEADERS    = {"Authorization": f"ApiKey {os.environ['ELASTIC_API_KEY']}", "kbn-xsrf": "true"}

INDEX   = "fleet-agents-health"
DASH_ID = "2c0a3d73-d7e6-4841-8731-437a14471cf1"


def sync_agents():
    es = Elasticsearch(ES_URL, api_key=os.environ["ELASTIC_API_KEY"])

    r = requests.get(f"{KIBANA_URL}/api/fleet/agents?perPage=100&showInactive=true", headers=HEADERS)
    agents = r.json().get("items", [])

    if not es.indices.exists(index=INDEX):
        es.indices.create(index=INDEX, body={"mappings": {"properties": {
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
        }}})
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
    print(f"Synced {len(agents)} agents at {now} | Online: {online} | Offline: {offline}")


def build_dashboard():
    metric_id = str(uuid.uuid4())
    pie_id    = str(uuid.uuid4())
    table_id  = str(uuid.uuid4())

    def vega_vis(id_, title, spec):
        return {
            "type": "visualization", "id": id_,
            "attributes": {
                "title": title,
                "visState": json.dumps({"type": "vega", "aggs": [], "params": {"spec": json.dumps(spec, indent=2)}}),
                "uiStateJSON": "{}",
                "description": "",
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({"query": {"language": "kuery", "query": ""}, "filter": []})
                }
            },
            "references": []
        }

    metric_spec = {
        "$schema": "https://vega.github.io/schema/vega/v5.json",
        "data": [
            {
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
            }
        ],
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
                    "fontSize": {"value": 13},
                    "align": {"value": "center"},
                    "fill": {"value": "#69707D"}
                }}
            }
        ]
    }

    pie_spec = {
        "$schema": "https://vega.github.io/schema/vega/v5.json",
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
        "legends": [{"fill": "color", "title": "Status", "orient": "right", "labelFontSize": 12, "titleFontSize": 12}],
        "marks": [
            {
                "type": "arc", "from": {"data": "pie"},
                "encode": {"enter": {
                    "x": {"signal": "width / 2 - 30"},
                    "y": {"signal": "height / 2"},
                    "startAngle": {"field": "startAngle"},
                    "endAngle": {"field": "endAngle"},
                    "innerRadius": {"signal": "min(width, height) / 4"},
                    "outerRadius": {"signal": "min(width, height) / 2.8"},
                    "fill": {"scale": "color", "field": "key"},
                    "stroke": {"value": "#fff"},
                    "strokeWidth": {"value": 2}
                }}
            },
            {
                "type": "text", "from": {"data": "pie"},
                "encode": {"enter": {
                    "x": {"signal": "width / 2 - 30"},
                    "y": {"signal": "height / 2"},
                    "radius": {"signal": "min(width, height) / 2.8 + 16"},
                    "theta": {"signal": "(datum.startAngle + datum.endAngle) / 2"},
                    "text": {"signal": "datum.key + ' (' + datum.doc_count + ')'"},
                    "align": {"value": "center"},
                    "baseline": {"value": "middle"},
                    "fontSize": {"value": 11},
                    "fontWeight": {"value": "bold"},
                    "fill": {"value": "#343741"}
                }}
            }
        ]
    }

    table_spec = {
        "$schema": "https://vega.github.io/schema/vega/v5.json",
        "data": [{
            "name": "agents",
            "url": {
                "index": INDEX,
                "body": {
                    "size": 50,
                    "_source": ["hostname", "status", "agent_version", "last_checkin"],
                    "sort": [{"hostname": {"order": "asc"}}]
                }
            },
            "format": {"property": "hits.hits"},
            "transform": [
                {"type": "formula", "as": "hostname", "expr": "datum._source.hostname"},
                {"type": "formula", "as": "status",   "expr": "datum._source.status"},
                {"type": "formula", "as": "version",  "expr": "datum._source.agent_version"},
                {"type": "formula", "as": "checkin",  "expr": "slice(datum._source.last_checkin, 0, 19)"},
                {"type": "window", "ops": ["row_number"], "as": ["rn"]},
                {"type": "formula", "as": "y",        "expr": "datum.rn * 26 + 30"}
            ]
        }],
        "scales": [{
            "name": "sc", "type": "ordinal",
            "domain": ["online", "offline", "degraded"],
            "range": ["#007871", "#BD271E", "#F5A700"]
        }],
        "marks": [
            {"type": "rule", "encode": {"enter": {"x": {"value": 0}, "x2": {"signal": "width"}, "y": {"value": 22}, "stroke": {"value": "#D3DAE6"}, "strokeWidth": {"value": 1}}}},
            {"type": "text", "encode": {"enter": {"x": {"value": 0},   "y": {"value": 14}, "text": {"value": "HOSTNAME"},     "fontWeight": {"value": "bold"}, "fill": {"value": "#343741"}, "fontSize": {"value": 11}}}},
            {"type": "text", "encode": {"enter": {"x": {"value": 260}, "y": {"value": 14}, "text": {"value": "STATUS"},       "fontWeight": {"value": "bold"}, "fill": {"value": "#343741"}, "fontSize": {"value": 11}}}},
            {"type": "text", "encode": {"enter": {"x": {"value": 360}, "y": {"value": 14}, "text": {"value": "VERSION"},      "fontWeight": {"value": "bold"}, "fill": {"value": "#343741"}, "fontSize": {"value": 11}}}},
            {"type": "text", "encode": {"enter": {"x": {"value": 470}, "y": {"value": 14}, "text": {"value": "LAST CHECK-IN"},"fontWeight": {"value": "bold"}, "fill": {"value": "#343741"}, "fontSize": {"value": 11}}}},
            {"type": "text", "from": {"data": "agents"}, "encode": {"enter": {"x": {"value": 0},   "y": {"field": "y"}, "text": {"field": "hostname"}, "fill": {"value": "#343741"},                "fontSize": {"value": 11}, "limit": {"value": 255}}}},
            {"type": "text", "from": {"data": "agents"}, "encode": {"enter": {"x": {"value": 260}, "y": {"field": "y"}, "text": {"field": "status"},   "fill": {"scale": "sc", "field": "status"}, "fontSize": {"value": 11}, "fontWeight": {"value": "bold"}}}},
            {"type": "text", "from": {"data": "agents"}, "encode": {"enter": {"x": {"value": 360}, "y": {"field": "y"}, "text": {"field": "version"},  "fill": {"value": "#343741"},                "fontSize": {"value": 11}}}},
            {"type": "text", "from": {"data": "agents"}, "encode": {"enter": {"x": {"value": 470}, "y": {"field": "y"}, "text": {"field": "checkin"},  "fill": {"value": "#343741"},                "fontSize": {"value": 11}}}}
        ]
    }

    panels = [
        {"type": "visualization", "gridData": {"x": 0, "y": 0, "w": 8,  "h": 8,  "i": "p1"}, "panelIndex": "p1", "embeddableConfig": {"enhancements": {}}, "panelRefName": "panel_0"},
        {"type": "visualization", "gridData": {"x": 8, "y": 0, "w": 16, "h": 8,  "i": "p2"}, "panelIndex": "p2", "embeddableConfig": {"enhancements": {}}, "panelRefName": "panel_1"},
        {"type": "visualization", "gridData": {"x": 0, "y": 8, "w": 24, "h": 12, "i": "p3"}, "panelIndex": "p3", "embeddableConfig": {"enhancements": {}}, "panelRefName": "panel_2"},
    ]

    objects = [
        vega_vis(metric_id, "Online Agents",            metric_spec),
        vega_vis(pie_id,    "Agent Status Distribution", pie_spec),
        vega_vis(table_id,  "Agent Details",             table_spec),
        {
            "type": "dashboard", "id": DASH_ID,
            "attributes": {
                "title": "Agent Health Overview",
                "description": "Fleet agent health: online count, status distribution, and per-agent details",
                "panelsJSON": json.dumps(panels),
                "optionsJSON": json.dumps({"useMargins": True, "syncColors": False, "hidePanelTitles": False}),
                "timeRestore": False,
                "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"language": "kuery", "query": ""}, "filter": []})}
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
        headers=HEADERS,
        files={"file": ("export.ndjson", io.BytesIO(ndjson.encode()), "application/ndjson")}
    )
    resp = r.json()
    print(f"Dashboard import: {resp.get('successCount')}/{len(objects)} succeeded")
    print(f"URL: {KIBANA_URL}/app/dashboards#/view/{DASH_ID}")


if __name__ == "__main__":
    sync_agents()
    build_dashboard()