#!/usr/bin/env python3
"""
AI Security Monitor
Creates Kibana SIEM detection rules and an AI Activity dashboard.
Monitors AI service usage across all Elastic Defend endpoints.

Usage:
  python create_ai_security_monitor.py                  # rules + dashboard
  python create_ai_security_monitor.py --rules-only
  python create_ai_security_monitor.py --dashboard-only
"""

import os, json, uuid, sys, io
import requests
from datetime import datetime, timezone

KIBANA_URL = os.environ.get("KIBANA_URL", "https://my-security-project-aac892.kb.us-east-2.aws.elastic.cloud")
ES_URL     = os.environ.get("ES_URL",     "https://my-security-project-aac892.es.us-east-2.aws.elastic.cloud")
API_KEY    = os.environ["ELASTIC_API_KEY"]
HEADERS    = {"Authorization": f"ApiKey {API_KEY}", "kbn-xsrf": "true", "Content-Type": "application/json"}

NET_INDEX  = "logs-endpoint.events.network-*"
DASH_ID    = "ai-security-activity-001"

AI_DOMAINS_KQL = (
    "dns.question.name: (*openai* or *anthropic* or *claude.ai* or "
    "*gemini.google* or *copilot.microsoft* or *githubcopilot* or "
    "*mistral.ai* or *huggingface* or *cohere* or *perplexity* or *ollama*)"
)

SERVICE_MAP_EXPR = (
    "indexof(datum.key, 'anthropic') >= 0 || indexof(datum.key, 'claude') >= 0 ? 'Anthropic / Claude' : "
    "indexof(datum.key, 'copilot') >= 0 || indexof(datum.key, 'githubcopilot') >= 0 ? 'GitHub Copilot' : "
    "indexof(datum.key, 'gemini') >= 0 ? 'Google Gemini' : "
    "indexof(datum.key, 'openai') >= 0 ? 'OpenAI' : "
    "indexof(datum.key, 'mistral') >= 0 ? 'Mistral AI' : "
    "indexof(datum.key, 'huggingface') >= 0 ? 'HuggingFace' : "
    "indexof(datum.key, 'ollama') >= 0 ? 'Ollama (Local)' : "
    "indexof(datum.key, 'perplexity') >= 0 ? 'Perplexity' : "
    "indexof(datum.key, 'cohere') >= 0 ? 'Cohere' : datum.key"
)


# ── 1. DETECTION RULES ────────────────────────────────────────
def create_detection_rules():
    rules = [
        {
            "rule_id":     "ai-service-access-detected",
            "name":        "AI Service Access Detected",
            "description": "An endpoint made a DNS request to a known AI service provider. Informational — review for policy compliance.",
            "severity":    "low",
            "risk_score":  21,
            "type":        "query",
            "language":    "kuery",
            "query":       AI_DOMAINS_KQL,
            "index":       [NET_INDEX],
            "interval":    "5m",
            "from":        "now-6m",
            "enabled":     True,
            "tags":        ["AI Security", "Network", "Informational"],
            "references":  [],
            "false_positives": ["Sanctioned AI tools used during business hours"],
            "threat":      []
        },
        {
            "rule_id":     "high-volume-ai-api-calls",
            "name":        "High Volume AI API Calls",
            "description": "A single host made more than 100 DNS requests to AI service providers within 15 minutes. May indicate automated AI usage, scripted queries, or data exfiltration via AI APIs.",
            "severity":    "medium",
            "risk_score":  47,
            "type":        "threshold",
            "language":    "kuery",
            "query":       AI_DOMAINS_KQL,
            "index":       [NET_INDEX],
            "interval":    "15m",
            "from":        "now-16m",
            "enabled":     True,
            "tags":        ["AI Security", "Network", "Exfiltration"],
            "threshold": {
                "field": ["host.name"],
                "value": 100
            },
            "threat": []
        },
        {
            "rule_id":     "unsanctioned-local-ai-tool",
            "name":        "Unsanctioned Local AI Tool Detected",
            "description": "A process associated with a locally-run AI model (Ollama, LM Studio, GPT4All) was detected making network requests. Local LLMs bypass corporate AI monitoring and data controls.",
            "severity":    "high",
            "risk_score":  73,
            "type":        "query",
            "language":    "kuery",
            "query":       "dns.question.name: (*ollama* or *lmstudio* or *gpt4all* or *localai*) or process.name: (ollama or \"LM Studio\" or gpt4all)",
            "index":       [NET_INDEX],
            "interval":    "5m",
            "from":        "now-6m",
            "enabled":     True,
            "tags":        ["AI Security", "Shadow AI", "High Priority"],
            "threat":      []
        },
        {
            "rule_id":     "after-hours-ai-usage",
            "name":        "After Hours AI Service Access",
            "description": "AI service access detected outside standard business hours (before 6AM or after 11PM UTC). May indicate unauthorized use, compromised credentials, or automated exfiltration.",
            "severity":    "medium",
            "risk_score":  47,
            "type":        "eql",
            "language":    "eql",
            "query": (
                "network where (\n"
                "  dns.question.name like~ ('*openai*', '*anthropic*', '*claude.ai*',\n"
                "    '*gemini.google*', '*copilot.microsoft*', '*githubcopilot*',\n"
                "    '*mistral.ai*', '*huggingface*', '*ollama*')\n"
                ") and (\n"
                "  hourOfDay(@timestamp) < 6 or hourOfDay(@timestamp) >= 23\n"
                ")"
            ),
            "index":    [NET_INDEX],
            "interval": "15m",
            "from":     "now-16m",
            "enabled":  True,
            "tags":     ["AI Security", "After Hours", "Behavioral"],
            "threat":   []
        }
    ]

    created = 0
    updated = 0
    failed  = 0

    for rule in rules:
        # Try update first, then create
        r = requests.put(
            f"{KIBANA_URL}/api/detection_engine/rules",
            headers=HEADERS,
            json=rule,
            timeout=15
        )
        if r.status_code in (200, 201):
            updated += 1
            print(f"  ✓ [{rule['severity'].upper():6}] {rule['name']}")
        else:
            r2 = requests.post(
                f"{KIBANA_URL}/api/detection_engine/rules",
                headers=HEADERS,
                json=rule,
                timeout=15
            )
            if r2.status_code in (200, 201):
                created += 1
                print(f"  + [{rule['severity'].upper():6}] {rule['name']}")
            else:
                failed += 1
                print(f"  ✗ [{rule['severity'].upper():6}] {rule['name']} — {r2.status_code}: {r2.json().get('message','')}")

    print(f"\nRules: {created} created, {updated} updated, {failed} failed")


# ── 2. AI ACTIVITY DASHBOARD ──────────────────────────────────
def build_dashboard():
    timeline_id = str(uuid.uuid4())
    service_id  = str(uuid.uuid4())
    host_id     = str(uuid.uuid4())
    table_id    = str(uuid.uuid4())

    AI_FILTER = {
        "bool": {
            "should": [
                {"wildcard": {"dns.question.name": {"value": "*openai*"}}},
                {"wildcard": {"dns.question.name": {"value": "*anthropic*"}}},
                {"wildcard": {"dns.question.name": {"value": "*claude.ai*"}}},
                {"wildcard": {"dns.question.name": {"value": "*gemini.google*"}}},
                {"wildcard": {"dns.question.name": {"value": "*copilot.microsoft*"}}},
                {"wildcard": {"dns.question.name": {"value": "*githubcopilot*"}}},
                {"wildcard": {"dns.question.name": {"value": "*mistral.ai*"}}},
                {"wildcard": {"dns.question.name": {"value": "*huggingface*"}}},
                {"wildcard": {"dns.question.name": {"value": "*ollama*"}}},
                {"wildcard": {"dns.question.name": {"value": "*cohere*"}}},
                {"wildcard": {"dns.question.name": {"value": "*perplexity*"}}}
            ],
            "minimum_should_match": 1
        }
    }

    # ── Panel 1: Timeline ─────────────────────────────────────
    timeline_spec = {
        "$schema": "https://vega.github.io/schema/vega/v5.json",
        "padding": 10,
        "data": [{
            "name": "events",
            "url": {
                "index": NET_INDEX,
                "body": {
                    "size": 0,
                    "query": AI_FILTER,
                    "aggs": {
                        "over_time": {
                            "date_histogram": {
                                "field": "@timestamp",
                                "fixed_interval": "6h",
                                "extended_bounds": {"min": "now-7d", "max": "now"}
                            }
                        }
                    }
                }
            },
            "format": {"property": "aggregations.over_time.buckets"},
            "transform": [
                {"type": "formula", "as": "date",  "expr": "datetime(datum.key)"},
                {"type": "formula", "as": "count", "expr": "datum.doc_count"}
            ]
        }],
        "scales": [
            {"name": "x", "type": "time",   "range": "width",  "domain": {"data": "events", "field": "date"}},
            {"name": "y", "type": "linear", "range": "height", "domain": {"data": "events", "field": "count"}, "nice": True, "zero": True}
        ],
        "axes": [
            {"orient": "bottom", "scale": "x", "labelColor": "#FFFFFF", "tickColor": "#555", "domainColor": "#555", "format": "%b %d", "labelAngle": -30, "labelFontSize": 11},
            {"orient": "left",   "scale": "y", "labelColor": "#FFFFFF", "tickColor": "#555", "domainColor": "#555", "grid": True, "gridColor": "#2a2a2a", "labelFontSize": 11}
        ],
        "marks": [{
            "type": "area",
            "from": {"data": "events"},
            "encode": {
                "enter": {
                    "x":       {"scale": "x", "field": "date"},
                    "y":       {"scale": "y", "field": "count"},
                    "y2":      {"scale": "y", "value": 0},
                    "fill":    {"value": "#007871"},
                    "fillOpacity": {"value": 0.6},
                    "stroke":  {"value": "#00b3a4"},
                    "strokeWidth": {"value": 2}
                }
            }
        }]
    }

    # ── Panel 2: Service Breakdown ────────────────────────────
    service_spec = {
        "$schema": "https://vega.github.io/schema/vega/v5.json",
        "padding": 10,
        "data": [
            {
                "name": "raw",
                "url": {
                    "index": NET_INDEX,
                    "body": {
                        "size": 0,
                        "query": AI_FILTER,
                        "aggs": {"by_domain": {"terms": {"field": "dns.question.name", "size": 20}}}
                    }
                },
                "format": {"property": "aggregations.by_domain.buckets"},
                "transform": [
                    {"type": "formula", "as": "service", "expr": SERVICE_MAP_EXPR}
                ]
            },
            {
                "name": "grouped",
                "source": "raw",
                "transform": [
                    {"type": "aggregate", "groupby": ["service"], "ops": ["sum"], "fields": ["doc_count"], "as": ["total"]}
                ]
            },
            {
                "name": "pie", "source": "grouped",
                "transform": [{"type": "pie", "field": "total"}]
            }
        ],
        "scales": [{
            "name": "color", "type": "ordinal",
            "range": ["#007871","#00b3a4","#F5A700","#BD271E","#6092C0","#D36086","#9170B8","#CA8EAE","#D6BF57"]
        }],
        "legends": [{"fill": "color", "title": "Service", "orient": "right",
                     "labelColor": "#FFFFFF", "titleColor": "#FFFFFF",
                     "labelFontSize": 12, "titleFontSize": 12}],
        "marks": [
            {
                "type": "arc", "from": {"data": "pie"},
                "encode": {"enter": {
                    "x": {"signal": "width / 2 - 40"},
                    "y": {"signal": "height / 2"},
                    "startAngle": {"field": "startAngle"},
                    "endAngle":   {"field": "endAngle"},
                    "innerRadius": {"signal": "min(width, height) / 4.5"},
                    "outerRadius": {"signal": "min(width, height) / 2.8"},
                    "fill":   {"scale": "color", "field": "service"},
                    "stroke": {"value": "#1a1a2e"},
                    "strokeWidth": {"value": 2}
                }}
            },
            {
                "type": "text", "from": {"data": "pie"},
                "encode": {"enter": {
                    "x": {"signal": "width / 2 - 40"},
                    "y": {"signal": "height / 2"},
                    "radius": {"signal": "min(width, height) / 2.8 + 14"},
                    "theta":  {"signal": "(datum.startAngle + datum.endAngle) / 2"},
                    "text":   {"signal": "datum.total > 20 ? datum.service : ''"},
                    "align":  {"value": "center"},
                    "baseline": {"value": "middle"},
                    "fontSize": {"value": 11},
                    "fontWeight": {"value": "bold"},
                    "fill": {"value": "#FFFFFF"}
                }}
            }
        ]
    }

    # ── Panel 3: Usage by Host ────────────────────────────────
    host_spec = {
        "$schema": "https://vega.github.io/schema/vega/v5.json",
        "padding": 10,
        "data": [{
            "name": "hosts",
            "url": {
                "index": NET_INDEX,
                "body": {
                    "size": 0,
                    "query": AI_FILTER,
                    "aggs": {"by_host": {"terms": {"field": "host.name", "size": 15, "order": {"_count": "desc"}}}}
                }
            },
            "format": {"property": "aggregations.by_host.buckets"},
            "transform": [
                {"type": "formula", "as": "host",  "expr": "datum.key"},
                {"type": "formula", "as": "count", "expr": "datum.doc_count"}
            ]
        }],
        "scales": [
            {"name": "y", "type": "band",   "range": "height", "domain": {"data": "hosts", "field": "host"}, "padding": 0.2},
            {"name": "x", "type": "linear", "range": "width",  "domain": {"data": "hosts", "field": "count"}, "nice": True, "zero": True}
        ],
        "axes": [
            {"orient": "left",   "scale": "y", "labelColor": "#FFFFFF", "domainColor": "#555", "tickColor": "#555", "labelFontSize": 12},
            {"orient": "bottom", "scale": "x", "labelColor": "#FFFFFF", "domainColor": "#555", "tickColor": "#555", "grid": True, "gridColor": "#2a2a2a", "labelFontSize": 11}
        ],
        "marks": [
            {
                "type": "rect", "from": {"data": "hosts"},
                "encode": {"enter": {
                    "y":      {"scale": "y", "field": "host"},
                    "height": {"scale": "y", "band": 1},
                    "x":      {"scale": "x", "value": 0},
                    "x2":     {"scale": "x", "field": "count"},
                    "fill":   {"value": "#006BB4"},
                    "cornerRadiusTopRight":    {"value": 3},
                    "cornerRadiusBottomRight": {"value": 3}
                }}
            },
            {
                "type": "text", "from": {"data": "hosts"},
                "encode": {"enter": {
                    "x":       {"scale": "x", "field": "count", "offset": 6},
                    "y":       {"scale": "y", "field": "host",  "band": 0.5},
                    "text":    {"field": "count"},
                    "baseline":{"value": "middle"},
                    "fill":    {"value": "#FFFFFF"},
                    "fontSize":{"value": 12},
                    "fontWeight": {"value": "bold"}
                }}
            }
        ]
    }

    # ── Panel 4: Recent Activity Table ────────────────────────
    table_spec = {
        "$schema": "https://vega.github.io/schema/vega/v5.json",
        "padding": 10,
        "data": [{
            "name": "activity",
            "url": {
                "index": NET_INDEX,
                "body": {
                    "size": 40,
                    "query": AI_FILTER,
                    "_source": ["@timestamp", "host.name", "user.name", "process.name", "dns.question.name"],
                    "sort": [{"@timestamp": {"order": "desc"}}]
                }
            },
            "format": {"property": "hits.hits"},
            "transform": [
                {"type": "formula", "as": "ts",      "expr": "slice(datum._source['@timestamp'], 0, 19)"},
                {"type": "formula", "as": "host",    "expr": "datum._source['host.name'] || datum._source.host.name"},
                {"type": "formula", "as": "user",    "expr": "datum._source['user.name'] || datum._source.user.name"},
                {"type": "formula", "as": "process", "expr": "datum._source['process.name'] || datum._source.process.name"},
                {"type": "formula", "as": "domain",  "expr": "datum._source['dns.question.name'] || datum._source.dns.question.name"},
                {"type": "formula", "as": "service", "expr": SERVICE_MAP_EXPR.replace("datum.key", "datum.domain")},
                {"type": "window",  "ops": ["row_number"], "as": ["rn"]},
                {"type": "formula", "as": "y", "expr": "datum.rn * 28 + 32"}
            ]
        }],
        "signals": [{"name": "height", "update": "length(data('activity')) * 28 + 52"}],
        "scales": [{
            "name": "svc_color", "type": "ordinal",
            "domain": ["Anthropic / Claude", "GitHub Copilot", "Google Gemini", "OpenAI", "Mistral AI", "HuggingFace", "Ollama (Local)", "Perplexity", "Cohere"],
            "range":  ["#00b3a4",            "#6092C0",        "#F5A700",       "#BD271E", "#9170B8",   "#D36086",      "#CA8EAE",       "#D6BF57",    "#007871"]
        }],
        "marks": [
            {"type": "rule", "encode": {"enter": {"x": {"value": 0}, "x2": {"signal": "width"}, "y": {"value": 24}, "stroke": {"value": "#444"}, "strokeWidth": {"value": 1}}}},
            {"type": "text", "encode": {"enter": {"x": {"value": 0},   "y": {"value": 15}, "text": {"value": "TIMESTAMP"},  "fontWeight": {"value": "bold"}, "fill": {"value": "#FFFFFF"}, "fontSize": {"value": 12}}}},
            {"type": "text", "encode": {"enter": {"x": {"value": 155}, "y": {"value": 15}, "text": {"value": "HOST"},       "fontWeight": {"value": "bold"}, "fill": {"value": "#FFFFFF"}, "fontSize": {"value": 12}}}},
            {"type": "text", "encode": {"enter": {"x": {"value": 310}, "y": {"value": 15}, "text": {"value": "USER"},       "fontWeight": {"value": "bold"}, "fill": {"value": "#FFFFFF"}, "fontSize": {"value": 12}}}},
            {"type": "text", "encode": {"enter": {"x": {"value": 420}, "y": {"value": 15}, "text": {"value": "PROCESS"},    "fontWeight": {"value": "bold"}, "fill": {"value": "#FFFFFF"}, "fontSize": {"value": 12}}}},
            {"type": "text", "encode": {"enter": {"x": {"value": 570}, "y": {"value": 15}, "text": {"value": "AI SERVICE"}, "fontWeight": {"value": "bold"}, "fill": {"value": "#FFFFFF"}, "fontSize": {"value": 12}}}},
            {"type": "text", "from": {"data": "activity"}, "encode": {"enter": {"x": {"value": 0},   "y": {"field": "y"}, "text": {"field": "ts"},      "fill": {"value": "#FFFFFF"},                       "fontSize": {"value": 12}, "limit": {"value": 150}}}},
            {"type": "text", "from": {"data": "activity"}, "encode": {"enter": {"x": {"value": 155}, "y": {"field": "y"}, "text": {"field": "host"},    "fill": {"value": "#FFFFFF"},                       "fontSize": {"value": 12}, "limit": {"value": 150}}}},
            {"type": "text", "from": {"data": "activity"}, "encode": {"enter": {"x": {"value": 310}, "y": {"field": "y"}, "text": {"field": "user"},    "fill": {"value": "#FFFFFF"},                       "fontSize": {"value": 12}, "limit": {"value": 100}}}},
            {"type": "text", "from": {"data": "activity"}, "encode": {"enter": {"x": {"value": 420}, "y": {"field": "y"}, "text": {"field": "process"}, "fill": {"value": "#FFFFFF"},                       "fontSize": {"value": 12}, "limit": {"value": 140}}}},
            {"type": "text", "from": {"data": "activity"}, "encode": {"enter": {"x": {"value": 570}, "y": {"field": "y"}, "text": {"field": "service"}, "fill": {"scale": "svc_color", "field": "service"}, "fontSize": {"value": 12}, "fontWeight": {"value": "bold"}, "limit": {"value": 150}}}}
        ]
    }

    def vega_obj(obj_id, title, spec):
        return {
            "type": "visualization",
            "id":   obj_id,
            "coreMigrationVersion": "9.0.0",
            "attributes": {
                "title": title,
                "visState": json.dumps({"type": "vega", "aggs": [], "params": {"spec": json.dumps(spec, indent=2)}}),
                "uiStateJSON": "{}",
                "description": "",
                "version": 1,
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({"query": {"language": "kuery", "query": ""}, "filter": []})
                }
            },
            "references": []
        }

    panels = [
        {"type": "visualization", "gridData": {"x": 0,  "y": 0,  "w": 24, "h": 10, "i": "p1"}, "panelIndex": "p1", "embeddableConfig": {"enhancements": {}}, "panelRefName": "panel_0"},
        {"type": "visualization", "gridData": {"x": 0,  "y": 10, "w": 12, "h": 12, "i": "p2"}, "panelIndex": "p2", "embeddableConfig": {"enhancements": {}}, "panelRefName": "panel_1"},
        {"type": "visualization", "gridData": {"x": 12, "y": 10, "w": 12, "h": 12, "i": "p3"}, "panelIndex": "p3", "embeddableConfig": {"enhancements": {}}, "panelRefName": "panel_2"},
        {"type": "visualization", "gridData": {"x": 0,  "y": 22, "w": 24, "h": 18, "i": "p4"}, "panelIndex": "p4", "embeddableConfig": {"enhancements": {}}, "panelRefName": "panel_3"},
    ]

    objects = [
        vega_obj(timeline_id, "AI Activity Timeline (7 days)", timeline_spec),
        vega_obj(service_id,  "AI Service Distribution",       service_spec),
        vega_obj(host_id,     "AI Usage by Host",              host_spec),
        vega_obj(table_id,    "Recent AI Activity",            table_spec),
        {
            "type": "dashboard",
            "id":   DASH_ID,
            "coreMigrationVersion": "9.0.0",
            "attributes": {
                "title":       "AI Security Activity Monitor",
                "description": "Monitors AI service usage across all endpoints — timeline, service breakdown, host activity, and recent events",
                "panelsJSON":  json.dumps(panels),
                "optionsJSON": json.dumps({"useMargins": True, "syncColors": False, "hidePanelTitles": False}),
                "timeRestore": False,
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({"query": {"language": "kuery", "query": ""}, "filter": []})
                }
            },
            "references": [
                {"type": "visualization", "id": timeline_id, "name": "panel_0"},
                {"type": "visualization", "id": service_id,  "name": "panel_1"},
                {"type": "visualization", "id": host_id,     "name": "panel_2"},
                {"type": "visualization", "id": table_id,    "name": "panel_3"}
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
    args           = sys.argv[1:]
    rules_only     = "--rules-only"     in args
    dashboard_only = "--dashboard-only" in args

    if rules_only:
        print("Creating detection rules...")
        create_detection_rules()
    elif dashboard_only:
        print("Building AI Activity dashboard...")
        build_dashboard()
    else:
        print("Creating detection rules...")
        create_detection_rules()
        print("\nBuilding AI Activity dashboard...")
        build_dashboard()
