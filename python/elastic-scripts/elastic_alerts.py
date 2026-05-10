import os
from elasticsearch import Elasticsearch

es = Elasticsearch(
    "https://my-security-project-aac892.es.us-east-2.aws.elastic.cloud",
    api_key=os.environ["ELASTIC_API_KEY"]
)

print(es.info())

results = es.search(index=".alerts-security.alerts-default", size=5, query={"match_all": {}})
for hit in results["hits"]["hits"]:
    print(hit["_source"].get("kibana.alert.rule.name"))