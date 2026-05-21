import boto3, os

def handler(event, context):
    client = boto3.client('secretsmanager', region_name='us-east-2')

    os.environ['ELASTIC_CLOUD_API_KEY_CLI'] = client.get_secret_value(
        SecretId='elastic/agent-health/api-key')['SecretString']
    os.environ['KIBANA_URL'] = client.get_secret_value(
        SecretId='elastic/agent-health/kibana-url')['SecretString']
    os.environ['ES_URL'] = client.get_secret_value(
        SecretId='elastic/agent-health/es-url')['SecretString']

    import create_agent_health_dashboard
    create_agent_health_dashboard.sync_agents()
    return {"status": "success"}
