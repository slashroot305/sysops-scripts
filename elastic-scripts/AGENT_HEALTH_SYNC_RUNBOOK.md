# Agent Health Sync — Runbook & Architecture Documentation

**Project:** Fleet Agent Health Dashboard — Automated Sync via AWS  
**Author:** sysops-scripts  
**Last Updated:** 2026-05-19  
**Status:** Design / Pre-Implementation

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Problem Statement](#2-problem-statement)
3. [Solution Overview](#3-solution-overview)
4. [Reference Architecture](#4-reference-architecture)
5. [Data Flow Diagram](#5-data-flow-diagram)
6. [Security Model](#6-security-model)
7. [Component Breakdown](#7-component-breakdown)
8. [Cost Analysis](#8-cost-analysis)
9. [Step-by-Step Runbook](#9-step-by-step-runbook)
10. [Verification & Testing](#10-verification--testing)
11. [Monitoring & Alerting](#11-monitoring--alerting)
12. [Rollback Plan](#12-rollback-plan)

---

## 1. Executive Summary

### For Non-Technical Stakeholders

This document describes how we keep your security dashboard up to date automatically, reliably, and securely — without any human having to press a button.

Think of your **Agent Health Dashboard** as a live scoreboard that shows which computers (called "agents") on your network are healthy, offline, or inactive. For that scoreboard to be accurate, it needs to receive fresh data regularly.

Previously, we relied on GitHub (a code hosting platform) to send that fresh data every 10 minutes. The problem: GitHub's scheduler is not guaranteed — it can be delayed by hours during busy periods, meaning your scoreboard could show outdated information without anyone knowing.

**The new solution** replaces GitHub's unreliable scheduler with Amazon Web Services (AWS) — a dedicated cloud platform built for exactly this kind of work. AWS guarantees that our data sync runs on time, every time. The sensitive credentials (passwords/keys) needed to access your security data are stored in **AWS Secrets Manager**, a vault purpose-built to protect secrets, with full audit logging of every access.

**End result:** Your dashboard reflects reality — always within 10 minutes of the current state of your network.

---

## 2. Problem Statement

| Issue | Impact |
|---|---|
| GitHub Actions cron is best-effort, not guaranteed | Dashboard data can be 1-2 hours stale |
| No alerting when sync fails | Silent failures go undetected |
| API key stored as GitHub Secret with no audit log | No visibility into who/what accessed it |
| No retry logic on transient failures | A single network hiccup breaks a sync cycle |

---

## 3. Solution Overview

We replace the GitHub Actions workflow with a fully managed, serverless AWS pipeline:

| Old | New |
|---|---|
| GitHub Actions cron (`*/10 * * * *`) | AWS EventBridge Scheduler (precise, guaranteed) |
| GitHub Secrets | AWS Secrets Manager (audited, rotatable) |
| GitHub-hosted runner | AWS Lambda (serverless, pay-per-use) |
| No retry | Lambda + EventBridge built-in retry |
| No monitoring | CloudWatch Logs + Alarms |

---

## 4. Reference Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                          AWS Cloud (us-east-2)                      │
│                                                                     │
│   ┌─────────────────────┐         ┌──────────────────────────────┐  │
│   │  EventBridge        │         │  AWS Secrets Manager         │  │
│   │  Scheduler          │         │                              │  │
│   │                     │         │  ┌──────────────────────┐    │  │
│   │  cron: */10 * * * * │         │  │ ELASTIC_API_KEY      │    │  │
│   │                     │         │  │ KIBANA_URL           │    │  │
│   └──────────┬──────────┘         │  │ ES_URL               │    │  │
│              │ triggers           │  └──────────────────────┘    │  │
│              │ every 10 min       └────────────┬─────────────────┘  │
│              ▼                                 │ reads secrets      │
│   ┌──────────────────────┐                     │                    │
│   │  AWS Lambda          │◄────────────────────┘                    │
│   │                      │                                          │
│   │  Python 3.11         │                                          │
│   │  create_agent_health │                                          │
│   │  _dashboard.py       │                                          │
│   │  --sync-only         │                                          │
│   └──────────┬───────────┘                                          │
│              │                          ┌───────────────────────┐   │
│              │                          │  CloudWatch           │   │
│              │ logs                     │                       │   │
│              ├─────────────────────────►│  - Execution logs     │   │
│              │                          │  - Duration metrics   │   │
│              │                          │  - Error alarms       │   │
│              │                          └───────────────────────┘   │
│   ┌──────────────────────┐                                          │
│   │  IAM Role            │                                          │
│   │  (Lambda Execution)  │                                          │
│   │                      │                                          │
│   │  Permissions:        │                                          │
│   │  - SecretsManager    │                                          │
│   │    GetSecretValue    │                                          │
│   │  - CloudWatch Logs   │                                          │
│   └──────────────────────┘                                          │
└─────────────────────────────────────────────────────────────────────┘
                    │
                    │ HTTPS (outbound only)
                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     Elastic Cloud (us-east-2)                       │
│                                                                     │
│   ┌──────────────────────┐      ┌──────────────────────────────┐    │
│   │  Fleet API           │      │  Elasticsearch               │    │
│   │  /api/fleet/agents   │      │  fleet-agents-health index   │    │
│   │                      │      │                              │    │
│   │  Returns: agent list │      │  Stores: synced agent data   │    │
│   │  with health status  │      │  (upsert by agent ID)        │    │
│   └──────────────────────┘      └──────────────────────────────┘    │
│                                          │                          │
│                                          ▼                          │
│                              ┌──────────────────────┐               │
│                              │  Kibana Dashboard    │               │
│                              │  Agent Health        │               │
│                              │  Overview            │               │
│                              │                      │               │
│                              │  - Online count      │               │
│                              │  - Status pie chart  │               │
│                              │  - Agent details     │               │
│                              └──────────────────────┘               │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 5. Data Flow Diagram

```
Every 10 Minutes:

  EventBridge                Lambda                  Elastic Cloud
  Scheduler                  Function                Fleet API
  ─────────                  ────────                ──────────
      │                          │                       │
      │──── triggers ───────────►│                       │
      │                          │                       │
      │                          │──── GET /api/fleet ──►│
      │                          │         /agents       │
      │                          │◄──── agent list ──────│
      │                          │       (9 agents)      │
      │                          │                       │
      │                   Secrets Manager                │
      │                   ──────────────                 │
      │                          │                       │
      │                          │──── GetSecretValue ──►│
      │                          │◄─── API key ──────────│
      │                          │                       │
      │                          │            Elasticsearch
      │                          │            ─────────────
      │                          │                       │
      │                          │──── upsert docs ─────►│
      │                          │    (1 per agent)      │
      │                          │◄─── confirmed ────────│
      │                          │                       │
      │                          │            CloudWatch
      │                          │            ──────────
      │                          │──── logs ────────────►│
      │                          │    "Synced 9 agents   │
      │                          │     Online: 2         │
      │                          │     Offline: 2"       │
      │                          │                       │
```

---

## 6. Security Model

```
┌─────────────────────────────────────────────────────┐
│              Security Boundaries                    │
│                                                     │
│  ┌─────────────────────────────────────────────┐    │
│  │  AWS Secrets Manager                        │    │
│  │                                             │    │
│  │  • Encrypted at rest (AES-256, AWS KMS)     │    │
│  │  • Encrypted in transit (TLS 1.2+)          │    │
│  │  • Full audit log via CloudTrail            │    │
│  │  • Access granted ONLY to Lambda IAM role   │    │
│  │  • No human access required at runtime      │    │
│  └─────────────────────────────────────────────┘    │
│                      │                              │
│            Least Privilege IAM                      │
│                      │                              │
│  ┌─────────────────────────────────────────────┐    │
│  │  Lambda IAM Role — Allowed Actions ONLY:    │    │
│  │                                             │    │
│  │  ✅ secretsmanager:GetSecretValue           │    │
│  │     (specific secret ARN only)              │    │
│  │  ✅ logs:CreateLogGroup                     │    │
│  │  ✅ logs:CreateLogStream                    │    │
│  │  ✅ logs:PutLogEvents                       │    │
│  │                                             │    │
│  │  ❌ secretsmanager:ListSecrets              │    │
│  │  ❌ secretsmanager:DeleteSecret             │    │
│  │  ❌ All other AWS actions                   │    │
│  └─────────────────────────────────────────────┘    │
│                      │                              │
│         Outbound-Only Network Communication         │
│                      │                              │
│  ┌─────────────────────────────────────────────┐    │
│  │  Lambda → Elastic Cloud                     │    │
│  │                                             │    │
│  │  • HTTPS only (port 443)                    │    │
│  │  • API key authentication                   │    │
│  │  • No inbound access to Lambda              │    │
│  │  • No VPC required (public endpoints)       │    │
│  └─────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────┘
```

---

## 7. Component Breakdown

### AWS EventBridge Scheduler
- Managed cron service — guaranteed execution, not best-effort
- Configured with cron: `*/10 * * * *` (every 10 minutes)
- Invokes Lambda directly with no intermediaries
- Built-in retry on Lambda throttling

### AWS Lambda
- Serverless compute — runs only when triggered, no idle cost
- Runtime: Python 3.11
- Memory: 128MB (sufficient for this workload)
- Timeout: 60 seconds (script typically completes in ~15s)
- Executes `create_agent_health_dashboard.py --sync-only`
- Packaged as a container image to handle dependency size

### AWS Secrets Manager
- Stores three secrets: `ELASTIC_API_KEY`, `KIBANA_URL`, `ES_URL`
- All secrets encrypted using AWS KMS
- Every access is logged to AWS CloudTrail
- Can be rotated without redeploying Lambda

### IAM Role (Least Privilege)
- Lambda assumes this role at execution time
- Grants only the minimum permissions needed
- No wildcard (`*`) actions or resources

### CloudWatch Logs
- All Lambda output (stdout/stderr) captured automatically
- Retention: 30 days (configurable)
- Basis for alerting on failures

---

## 8. Cost Analysis

| Component | Usage/Month | Unit Cost | Monthly Cost |
|---|---|---|---|
| EventBridge Scheduler | ~4,320 invocations | $1.00/million | ~$0.004 |
| Lambda compute | ~4,320 × 15s × 128MB | Free tier (400K GB-s) | $0.00 |
| Lambda requests | ~4,320 | Free tier (1M requests) | $0.00 |
| Secrets Manager | 3 secrets | $0.40/secret/month | $1.20 |
| Secrets Manager API | ~4,320 reads | $0.05/10K calls | $0.02 |
| CloudWatch Logs | ~10MB logs/month | $0.50/GB ingested | ~$0.01 |
| **Total** | | | **~$1.23/month** |

> All figures based on AWS us-east-2 pricing as of 2026. Lambda remains within free tier assuming no other Lambda usage in the account.

---

## 9. Step-by-Step Runbook

### Prerequisites

- [ ] AWS CLI installed and configured (`aws configure`)
- [ ] AWS account with permissions to create: Lambda, EventBridge, Secrets Manager, IAM
- [ ] Docker installed (for building Lambda container image)
- [ ] AWS ECR (Elastic Container Registry) access
- [ ] Python 3.11 installed locally
- [ ] `ELASTIC_CLOUD_API_KEY_CLI` set in local environment

---

### Step 1 — Store Secrets in AWS Secrets Manager

```bash
# Store Elastic API key
aws secretsmanager create-secret \
  --name "elastic/agent-health/api-key" \
  --description "Elastic Cloud API key for agent health sync" \
  --secret-string "$ELASTIC_CLOUD_API_KEY_CLI" \
  --region us-east-2 \
  --profile siem-logs

# Store Kibana URL
aws secretsmanager create-secret \
  --name "elastic/agent-health/kibana-url" \
  --description "Kibana endpoint URL" \
  --secret-string "https://my-security-project-aac892.kb.us-east-2.aws.elastic.cloud" \
  --region us-east-2 \
  --profile siem-logs

# Store Elasticsearch URL
aws secretsmanager create-secret \
  --name "elastic/agent-health/es-url" \
  --description "Elasticsearch endpoint URL" \
  --secret-string "https://my-security-project-aac892.es.us-east-2.aws.elastic.cloud" \
  --region us-east-2 \
  --profile siem-logs
```

**Verification:**
```bash
aws secretsmanager list-secrets \
  --region us-east-2 \
  --profile siem-logs \
  --query 'SecretList[?starts_with(Name, `elastic/`)].Name'
```

---

### Step 2 — Create IAM Role and Policy

**2a. Create the trust policy (allows Lambda to assume this role):**

```bash
cat > lambda-trust-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

aws iam create-role \
  --role-name elastic-agent-health-sync-role \
  --assume-role-policy-document file://lambda-trust-policy.json \
  --profile siem-logs
```

**2b. Create the permissions policy (least privilege):**

```bash
# Get the secret ARNs first
API_KEY_ARN=$(aws secretsmanager describe-secret --secret-id elastic/agent-health/api-key --region us-east-2 --profile siem-logs --query ARN --output text)
KIBANA_ARN=$(aws secretsmanager describe-secret --secret-id elastic/agent-health/kibana-url --region us-east-2 --profile siem-logs --query ARN --output text)
ES_ARN=$(aws secretsmanager describe-secret --secret-id elastic/agent-health/es-url --region us-east-2 --profile siem-logs --query ARN --output text)

cat > lambda-permissions-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SecretsManagerRead",
      "Effect": "Allow",
      "Action": "secretsmanager:GetSecretValue",
      "Resource": [
        "$API_KEY_ARN",
        "$KIBANA_ARN",
        "$ES_ARN"
      ]
    },
    {
      "Sid": "CloudWatchLogs",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:us-east-2:*:*"
    }
  ]
}
EOF

aws iam put-role-policy \
  --role-name elastic-agent-health-sync-role \
  --policy-name elastic-agent-health-sync-policy \
  --policy-document file://lambda-permissions-policy.json \
  --profile siem-logs
```

---

### Step 3 — Package Lambda as Container Image

**3a. Create Dockerfile:**

```dockerfile
# Dockerfile
FROM public.ecr.aws/lambda/python:3.11

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY create_agent_health_dashboard.py .
COPY lambda_handler.py .

CMD ["lambda_handler.handler"]
```

**3b. Create Lambda handler wrapper:**

```python
# lambda_handler.py
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
```

**3c. Build and push to ECR:**

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text --profile siem-logs)
REGION=us-east-2
REPO=elastic-agent-health-sync

# Create ECR repository
aws ecr create-repository --repository-name $REPO --region $REGION --profile siem-logs

# Authenticate Docker to ECR
aws ecr get-login-password --region $REGION --profile siem-logs | \
  docker login --username AWS --password-stdin $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com

# Build and push
docker build -t $REPO .
docker tag $REPO:latest $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/$REPO:latest
docker push $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/$REPO:latest
```

---

### Step 4 — Create Lambda Function

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text --profile siem-logs)
ROLE_ARN=$(aws iam get-role --role-name elastic-agent-health-sync-role --query Role.Arn --output text --profile siem-logs)

aws lambda create-function \
  --function-name elastic-agent-health-sync \
  --package-type Image \
  --code ImageUri=$ACCOUNT_ID.dkr.ecr.us-east-2.amazonaws.com/elastic-agent-health-sync:latest \
  --role $ROLE_ARN \
  --memory-size 128 \
  --timeout 60 \
  --region us-east-2 \
  --profile siem-logs
```

---

### Step 5 — Create EventBridge Scheduler

```bash
LAMBDA_ARN=$(aws lambda get-function --function-name elastic-agent-health-sync --region us-east-2 --profile siem-logs --query Configuration.FunctionArn --output text)
SCHEDULER_ROLE_ARN=$(aws iam get-role --role-name elastic-agent-health-sync-role --query Role.Arn --output text --profile siem-logs)

aws scheduler create-schedule \
  --name elastic-agent-health-sync-schedule \
  --schedule-expression "rate(10 minutes)" \
  --flexible-time-window Mode=OFF \
  --target "{
    \"Arn\": \"$LAMBDA_ARN\",
    \"RoleArn\": \"$SCHEDULER_ROLE_ARN\",
    \"Input\": \"{}\"
  }" \
  --region us-east-2 \
  --profile siem-logs
```

> `Mode=OFF` on `flexible-time-window` means exact timing — no flexibility window allowed.

---

### Step 6 — Grant EventBridge Permission to Invoke Lambda

```bash
aws lambda add-permission \
  --function-name elastic-agent-health-sync \
  --statement-id EventBridgeSchedulerInvoke \
  --action lambda:InvokeFunction \
  --principal scheduler.amazonaws.com \
  --region us-east-2 \
  --profile siem-logs
```

---

### Step 7 — Set CloudWatch Alarm for Failures

```bash
aws cloudwatch put-metric-alarm \
  --alarm-name "elastic-agent-health-sync-failures" \
  --alarm-description "Alert when agent health sync Lambda fails" \
  --metric-name Errors \
  --namespace AWS/Lambda \
  --dimensions Name=FunctionName,Value=elastic-agent-health-sync \
  --statistic Sum \
  --period 600 \
  --evaluation-periods 1 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --treat-missing-data notBreaching \
  --region us-east-2 \
  --profile siem-logs
```

---

## 10. Verification & Testing

### Manual Lambda Invocation Test

```bash
aws lambda invoke \
  --function-name elastic-agent-health-sync \
  --payload '{}' \
  --region us-east-2 \
  --profile siem-logs \
  response.json && cat response.json
```

Expected output:
```json
{"status": "success"}
```

### Verify Data in Elasticsearch

```bash
python3 -c "
from elasticsearch import Elasticsearch
import os
from datetime import datetime, timezone
from dateutil import parser

es = Elasticsearch(
    'https://my-security-project-aac892.es.us-east-2.aws.elastic.cloud',
    api_key=os.environ['ELASTIC_CLOUD_API_KEY_CLI']
)
r = es.search(index='fleet-agents-health', size=1, body={
    'sort': [{'snapshot_time': {'order': 'desc'}}],
    '_source': ['snapshot_time']
})
last = r['hits']['hits'][0]['_source']['snapshot_time']
since = (datetime.now(timezone.utc) - parser.parse(last)).total_seconds() / 60
print(f'Last sync: {last} ({since:.1f} min ago)')
"
```

### Check CloudWatch Logs

```bash
aws logs tail /aws/lambda/elastic-agent-health-sync \
  --follow \
  --region us-east-2 \
  --profile siem-logs
```

---

## 11. Monitoring & Alerting

| What to Monitor | Where | Expected Value |
|---|---|---|
| Lambda error rate | CloudWatch → Lambda → Errors | 0 per 10-min window |
| Lambda duration | CloudWatch → Lambda → Duration | < 30 seconds |
| Sync staleness | Elasticsearch `snapshot_time` | < 15 minutes old |
| Secrets access | CloudTrail → secretsmanager events | Only Lambda role |

---

## 12. Rollback Plan

If the Lambda sync fails and needs to be rolled back to GitHub Actions:

1. Disable the EventBridge schedule:
```bash
aws scheduler update-schedule \
  --name elastic-agent-health-sync-schedule \
  --state DISABLED \
  --region us-east-2 \
  --profile siem-logs
```

2. Re-enable the GitHub Actions workflow from the Actions tab in GitHub (if previously disabled).

3. Investigate Lambda failure via CloudWatch logs before re-enabling.

---

*This document should be treated as a living runbook. Update it as the infrastructure evolves.*
