import os
from elasticsearch import Elasticsearch

es = Elasticsearch(
    os.environ["ES_URL"],
    api_key=os.environ["ELASTIC_CLOUD_API_KEY_CLI"]
)

print(es.info())

results = es.search(index=".alerts-security.alerts-default", size=5, query={"match_all": {}})
for hit in results["hits"]["hits"]:
    print(hit["_source"].get("kibana.alert.rule.name"))