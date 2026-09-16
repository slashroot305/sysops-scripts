# sysops-scripts

A collection of SysOps, security engineering, and automation scripts for AWS, Elastic Security, and cross-platform system administration.

---

## Repository Structure

```
sysops-scripts/
├── elastic-scripts/              # Elastic Security SIEM tooling
│   ├── rtr/                      # Run-script response action payloads
│   │   ├── linux-and-mac/        # macOS/Linux endpoint health collector
│   │   └── windows/              # Windows endpoint health collector
│   ├── create_agent_health_dashboard.py
│   ├── create_ai_security_monitor.py
│   ├── lambda_handler.py
│   ├── Dockerfile
│   ├── requirements.txt
│   └── AGENT_HEALTH_SYNC_RUNBOOK.md
├── crowdstrike-scripts/          # CrowdStrike Falcon sensor installers
│   ├── falcon-install-ubuntu.sh
│   ├── falcon-install-macos.sh
│   └── falcon-install-windows.ps1
├── aws/                          # AWS automation
│   ├── aws_cost_analyzer.py
│   ├── create_user_aws.py
│   └── delete_user.py
├── powershell/                   # Windows/PowerShell scripts
│   └── software_removal_check.ps1
├── bash/mac/                     # macOS Bash scripts
│   └── backup.sh
└── python/                       # Python utilities
    └── password_generator.py
```

---

## Scripts Overview

### Elastic Security

#### `create_agent_health_dashboard.py`
Syncs Fleet agent status to Elasticsearch and creates a Kibana dashboard with an online agent count, status distribution pie chart, and per-agent details table. Designed to run on a schedule via GitHub Actions or AWS Lambda (see runbook).

**Usage:**
```bash
python create_agent_health_dashboard.py               # sync + dashboard
python create_agent_health_dashboard.py --sync-only   # agent sync only
python create_agent_health_dashboard.py --dashboard-only
```

**Prerequisites:** `KIBANA_URL`, `ES_URL`, `ELASTIC_CLOUD_API_KEY_CLI` environment variables.

---

#### `create_ai_security_monitor.py`
Creates Kibana SIEM detection rules and AI activity dashboards that monitor AI service usage (OpenAI, Anthropic, Copilot, etc.) across all Elastic Defend endpoints. Includes detection rules for high-volume usage, after-hours access, and unsanctioned local AI tools.

**Usage:**
```bash
python create_ai_security_monitor.py                    # rules + all dashboards
python create_ai_security_monitor.py --rules-only
python create_ai_security_monitor.py --dashboard-only
python create_ai_security_monitor.py --detections-dashboard
```

---

#### `lambda_handler.py`
AWS Lambda handler that retrieves Elastic credentials from AWS Secrets Manager and invokes the agent health sync. Designed for serverless scheduled execution.

---

#### `Dockerfile`
Lambda container image for the agent health sync. Packages `lambda_handler.py` and `create_agent_health_dashboard.py` into an AWS Lambda Python 3.11 runtime. Deploy via ECR + Lambda for scheduled serverless execution.

---

#### `requirements.txt`
Python dependencies for elastic-scripts: `elasticsearch==9.4.0`, `requests>=2.31.0`.

---

#### `AGENT_HEALTH_SYNC_RUNBOOK.md`
Full architecture and step-by-step runbook for migrating the agent health sync from GitHub Actions to a serverless AWS pipeline (EventBridge Scheduler → Lambda → Secrets Manager). Includes cost analysis, IAM least-privilege policy, CloudWatch alerting, and rollback plan.

---

#### `rtr/linux-and-mac/endpoint_health_collector.py`
Run-script response action payload for macOS and Linux endpoints. Collects system info, logged-in users, recent logins, top processes, network connections, persistence mechanisms, security posture (SIP, Gatekeeper, FileVault), recently modified files, and disk usage. Outputs structured JSON for ingestion into Kibana.

---

#### `rtr/windows/endpoint_health_collector.ps1`
Windows equivalent of the endpoint health collector. Collects system info, user sessions, recent logins (Event ID 4624), top processes, network connections, persistence mechanisms (registry run keys, scheduled tasks, startup folder), Windows Defender status, BitLocker, firewall state, local admins, and disk usage.

---

### AWS

#### `aws_cost_analyzer.py`
Multi-account AWS cost analysis tool. Pulls cost and usage data across all linked accounts in an AWS Organization using Cost Explorer, breaks down spend by service, and identifies top cost drivers. Supports profile-based auth for cross-account access.

---

#### `create_user_aws.py`
Creates an IAM user via the AWS CLI.

**Usage:**
```bash
python create_user_aws.py <username>
```

---

#### `delete_user.py`
Interactively deletes an IAM user. Prompts for confirmation before deletion.

---

### PowerShell

#### `software_removal_check.ps1`
Validates software installation/removal across multiple detection methods (Windows services, installation folders, registry keys) and sends results to a Logscale/Humio endpoint. Includes a reusable `SendTo-Logscale` function. Uses Symantec Endpoint Protection as an example — customizable for any software.

**Configuration:**
1. Set the Logscale URL in `SendTo-Logscale`
2. Add your Logscale authentication token
3. Update the service name, folder path, and registry key for your target software

---

### Bash

#### `backup.sh`
Backs up a directory from one location to another using `rsync`. Validates source and destination paths before running and provides progress feedback.

**Configuration:** Edit the path variables at the top of the script.

---

### Python

#### `password_generator.py`
Generates a cryptographically secure 16-character random string using Python's `secrets` module.

**Usage:**
```bash
python3 password_generator.py
```

---

### CrowdStrike

#### `crowdstrike-scripts/falcon-install-ubuntu.sh`
Installs the CrowdStrike Falcon sensor on Ubuntu (16/18/20/22/24, x86_64 and arm64). Authenticates with the CrowdStrike API, downloads the N-1 sensor package, validates SHA256 integrity, installs via `dpkg`, retrieves the CCID from the API, registers the sensor, and runs a post-install health check.

**Usage:**
```bash
export CS_CLIENT_ID=your_client_id
export CS_CLIENT_SECRET=your_client_secret
sudo bash falcon-install-ubuntu.sh
```

---

#### `crowdstrike-scripts/falcon-install-macos.sh`
Installs the Falcon sensor on macOS (universal — arm64 and x86_64). Same API-driven flow as the Ubuntu script: authenticates, downloads N-1 installer, validates integrity, installs the `.pkg`, registers with CCID, and checks System Extension/Full Disk Access approval status.

**Usage:**
```bash
export CS_CLIENT_ID=your_client_id
export CS_CLIENT_SECRET=your_client_secret
export CS_BASE_URL=https://api.us-2.crowdstrike.com
sudo bash falcon-install-macos.sh
```

---

#### `crowdstrike-scripts/falcon-install-windows.ps1`
Installs the Falcon sensor on Windows. Authenticates with the CrowdStrike API, downloads the N-1 installer, validates SHA256 integrity, installs silently with the CCID, and polls the `CSFalconService` for a post-install health check.

**Usage (PowerShell as Administrator):**
```powershell
$env:CS_CLIENT_ID     = "your_client_id"
$env:CS_CLIENT_SECRET = "your_client_secret"
$env:CS_BASE_URL      = "https://api.us-2.crowdstrike.com"
.\falcon-install-windows.ps1
```

**Prerequisites:** PowerShell 7+, run as Administrator.

---

## Requirements

### Elastic Scripts
- Python 3.8+
- `elasticsearch`, `requests` (`pip install -r requirements.txt`)
- `KIBANA_URL`, `ES_URL`, `ELASTIC_CLOUD_API_KEY_CLI` environment variables

### AWS Scripts
- Python 3.6+
- AWS CLI configured (`aws configure`)
- `boto3` for cost analyzer

### CrowdStrike Scripts
- Bash 4.0+ (Ubuntu/macOS)
- `curl`, `jq` (auto-installed if missing on macOS via Homebrew or direct download)
- `CS_CLIENT_ID`, `CS_CLIENT_SECRET` env vars required for all three scripts
- `CS_BASE_URL` env var required for macOS and Windows scripts
- Run as root/Administrator
- Generate API credentials at https://falcon.crowdstrike.com/api-clients-and-keys

### PowerShell Scripts
- PowerShell 7+
- Network access to Logscale/Humio endpoint
- Administrator rights for registry/service checks

### Bash Scripts
- Bash 3.2+
- macOS: `osascript` available (pre-installed)
- `rsync` for backup script

---

## Security Considerations

- Never commit credentials or tokens to version control — use environment variables or a secrets manager
- The `software_removal_check.ps1` Logscale token is a placeholder; supply your own via a secure mechanism
- Generated passwords should be stored in a password manager, not transmitted over insecure channels

---

## License

MIT — see [LICENSE](LICENSE)
