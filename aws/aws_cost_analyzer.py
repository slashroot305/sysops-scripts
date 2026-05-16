#!/usr/bin/env python3
"""
AWS Cost Analyzer & Monitor Setup
───────────────────────────────────────────────────────────────
Detects single vs multi-account structure, analyzes billing,
identifies cost drivers, recommends reductions, and sets up
centralized monitoring. In multi-account orgs, all alerts roll
up to the management account.

Requirements:
  pip install boto3 python-dateutil

Usage:
  python3 aws_cost_analyzer.py --profile <profile> --email <alert-email>
  python3 aws_cost_analyzer.py --profile jojo-aws-management --email ops@example.com --budget 100
  python3 aws_cost_analyzer.py --profile my-profile --email me@example.com --skip-monitoring
"""

import boto3
import argparse
from datetime import date, timedelta
from botocore.exceptions import ClientError

# ── Constants ──────────────────────────────────────────────────
COMMON_REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-west-2", "eu-central-1",
    "ap-southeast-1", "ap-northeast-1",
]
SPIKE_MULTIPLIER   = 3      # flag days costing 3x the daily average
ANOMALY_THRESHOLD  = 10     # $ absolute impact to trigger anomaly alert
DEFAULT_BUDGET     = 50.0   # default monthly budget if not specified


# ── Output helpers ─────────────────────────────────────────────
def section(title):
    print(f"\n{'='*62}\n  {title}\n{'='*62}")

def sub(title):
    print(f"\n── {title}")

def ok(msg):   print(f"  ✓  {msg}")
def warn(msg): print(f"  ⚠  {msg}")
def info(msg): print(f"  →  {msg}")
def err(msg):  print(f"  ✗  {msg}")


# ── Date helpers ───────────────────────────────────────────────
def month_start(d=None):
    d = d or date.today()
    return d.replace(day=1)

def month_end(d=None):
    d = d or date.today()
    # first day of next month
    if d.month == 12:
        return date(d.year + 1, 1, 1)
    return date(d.year, d.month + 1, 1)

def prev_month_start():
    today = date.today()
    first = today.replace(day=1)
    return (first - timedelta(days=1)).replace(day=1)


# ══════════════════════════════════════════════════════════════
class AWSCostAnalyzer:

    def __init__(self, profile: str, alert_email: str, budget_limit: float):
        self.profile      = profile
        self.alert_email  = alert_email
        self.budget_limit = budget_limit
        self.session      = boto3.Session(profile_name=profile)

        # Populated in phase 1
        self.account_id          = None
        self.is_org              = False
        self.is_management       = False
        self.management_id       = None
        self.org_accounts        = []   # [{Id, Name, Email, Status}]

        # Populated in phase 2
        self.current_cost  = 0.0
        self.forecast_cost = 0.0
        self.prev_cost     = 0.0
        self.top_services  = []   # [(name, amount)]
        self.top_accounts  = []   # [(account_id, amount)]
        self.spike_days    = []   # [(date_str, amount, avg)]

        # Populated in phases 3-4
        self.recommendations = []
        self.idle_resources  = []

    # ──────────────────────────────────────────────────────────
    # PHASE 1 — Account Structure
    # ──────────────────────────────────────────────────────────
    def detect_structure(self):
        section("PHASE 1: ACCOUNT STRUCTURE DETECTION")

        sts = self.session.client("sts")
        self.account_id = sts.get_caller_identity()["Account"]
        info(f"Account ID: {self.account_id}")

        org = self.session.client("organizations")
        try:
            org_data = org.describe_organization()["Organization"]
            self.is_org        = True
            self.management_id = org_data["MasterAccountId"]
            self.is_management = (self.account_id == self.management_id)

            paginator = org.get_paginator("list_accounts")
            for page in paginator.paginate():
                self.org_accounts.extend(
                    [a for a in page["Accounts"] if a["Status"] == "ACTIVE"]
                )

            ok(f"AWS Organization detected — {len(self.org_accounts)} active accounts")
            info(f"Management account: {self.management_id}")
            info(f"Running as: {'MANAGEMENT' if self.is_management else 'MEMBER'} account")
            print()
            for a in self.org_accounts:
                tag = " ◀ management" if a["Id"] == self.management_id else ""
                print(f"    {a['Name']:30}  {a['Id']}  {a['Email']}{tag}")

            if not self.is_management:
                warn("Not running as management account — cost data limited to this account.")
                warn("Re-run with the management account profile for full org-wide analysis.")

        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDeniedException", "AWSOrganizationsNotInUseException"):
                info("Single account — not part of an AWS Organization")
            else:
                raise

    # ──────────────────────────────────────────────────────────
    # PHASE 2 — Cost Analysis
    # ──────────────────────────────────────────────────────────
    def analyze_costs(self):
        section("PHASE 2: COST ANALYSIS")
        ce    = self.session.client("ce")
        today = date.today()
        ms    = month_start().isoformat()
        ts    = today.isoformat()
        me    = month_end().isoformat()
        ps    = prev_month_start().isoformat()
        pe    = month_start().isoformat()

        # ── Current month total
        sub("Current Month")
        resp = ce.get_cost_and_usage(
            TimePeriod={"Start": ms, "End": ts},
            Granularity="MONTHLY",
            Metrics=["UnblendedCost"],
        )
        self.current_cost = float(
            resp["ResultsByTime"][0]["Total"]["UnblendedCost"]["Amount"]
        )
        info(f"Actual spend  ({ms} → {ts}): ${self.current_cost:.2f}")

        # ── Forecast
        try:
            if ts < me:
                f_resp = ce.get_cost_forecast(
                    TimePeriod={"Start": ts, "End": me},
                    Metric="UNBLENDED_COST",
                    Granularity="MONTHLY",
                )
                self.forecast_cost = self.current_cost + float(f_resp["Total"]["Amount"])
                info(f"Forecasted month total:         ${self.forecast_cost:.2f}")
        except Exception:
            pass

        # ── Previous month
        prev_resp = ce.get_cost_and_usage(
            TimePeriod={"Start": ps, "End": pe},
            Granularity="MONTHLY",
            Metrics=["UnblendedCost"],
        )
        self.prev_cost = float(
            prev_resp["ResultsByTime"][0]["Total"]["UnblendedCost"]["Amount"]
        )
        change = (
            (self.current_cost - self.prev_cost) / self.prev_cost * 100
            if self.prev_cost else 0
        )
        info(f"Previous month total:           ${self.prev_cost:.2f}  ({change:+.1f}% MoM)")
        if change > 50:
            warn(f"Cost rose {change:.0f}% vs last month — investigate new resources or usage spikes")
            self.recommendations.append(
                f"Cost rose {change:.0f}% MoM (${self.prev_cost:.2f} → ${self.current_cost:.2f}) — review what changed"
            )

        # ── By service
        sub("Top Services")
        svc_resp = ce.get_cost_and_usage(
            TimePeriod={"Start": ms, "End": ts},
            Granularity="MONTHLY",
            Metrics=["UnblendedCost"],
            GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
        )
        services = sorted(
            [
                (g["Keys"][0], float(g["Metrics"]["UnblendedCost"]["Amount"]))
                for g in svc_resp["ResultsByTime"][0]["Groups"]
                if float(g["Metrics"]["UnblendedCost"]["Amount"]) > 0.01
            ],
            key=lambda x: -x[1],
        )
        self.top_services = services[:10]
        for name, amt in self.top_services:
            pct = (amt / self.current_cost * 100) if self.current_cost else 0
            print(f"    ${amt:8.2f}  ({pct:4.1f}%)  {name}")

        # ── By account (management only)
        if self.is_management and self.is_org:
            sub("Spend by Account")
            acct_resp = ce.get_cost_and_usage(
                TimePeriod={"Start": ms, "End": ts},
                Granularity="MONTHLY",
                Metrics=["UnblendedCost"],
                GroupBy=[{"Type": "DIMENSION", "Key": "LINKED_ACCOUNT"}],
            )
            id_to_name = {a["Id"]: a["Name"] for a in self.org_accounts}
            accounts = sorted(
                [
                    (g["Keys"][0], float(g["Metrics"]["UnblendedCost"]["Amount"]))
                    for g in acct_resp["ResultsByTime"][0]["Groups"]
                    if float(g["Metrics"]["UnblendedCost"]["Amount"]) > 0.01
                ],
                key=lambda x: -x[1],
            )
            self.top_accounts = accounts
            for acct_id, amt in accounts:
                name = id_to_name.get(acct_id, acct_id)
                pct  = (amt / self.current_cost * 100) if self.current_cost else 0
                print(f"    ${amt:8.2f}  ({pct:4.1f}%)  {name} ({acct_id})")

        # ── Daily spike detection
        sub("Daily Spike Detection")
        daily_resp = ce.get_cost_and_usage(
            TimePeriod={"Start": ms, "End": ts},
            Granularity="DAILY",
            Metrics=["UnblendedCost"],
        )
        daily = [
            (r["TimePeriod"]["Start"], float(r["Total"]["UnblendedCost"]["Amount"]))
            for r in daily_resp["ResultsByTime"]
        ]
        billed = [amt for _, amt in daily if amt > 0]
        if billed:
            avg = sum(billed) / len(billed)
            for day, amt in daily:
                if amt >= avg * SPIKE_MULTIPLIER and amt >= 5:
                    self.spike_days.append((day, amt, avg))
                    warn(f"Spike {day}: ${amt:.2f}  ({amt/avg:.1f}x daily avg of ${avg:.2f})")
                    self.recommendations.append(
                        f"Cost spike on {day}: ${amt:.2f} ({amt/avg:.1f}x avg ${avg:.2f}/day) "
                        f"— check what ran that day in Cost Explorer"
                    )
            if not self.spike_days:
                ok(f"No spikes detected (daily avg ${avg:.2f}, threshold ${avg*SPIKE_MULTIPLIER:.2f})")

    # ──────────────────────────────────────────────────────────
    # PHASE 3 — Idle Resource Detection
    # ──────────────────────────────────────────────────────────
    def detect_idle_resources(self):
        section("PHASE 3: IDLE RESOURCE DETECTION")

        if self.is_management and self.is_org and len(self.org_accounts) > 1:
            info(
                "Multi-account org detected. For full org resource scan, this tool needs "
                "cross-account IAM roles (OrganizationAccountAccessRole) or run per-account."
            )
            info("Scanning management account resources now.")

        self._scan_account(self.session, self.account_id)

    def _scan_account(self, session, account_id):
        info(f"Scanning account {account_id} across {len(COMMON_REGIONS)} regions...")
        for region in COMMON_REGIONS:
            self._scan_region(session, region)

    def _scan_region(self, session, region):
        ec2 = session.client("ec2", region_name=region)
        try:
            # ── Idle Elastic IPs
            for eip in ec2.describe_addresses()["Addresses"]:
                if "AssociationId" not in eip:
                    msg = f"Idle EIP {eip['PublicIp']} in {region} (~$3.65/mo)"
                    warn(msg)
                    self.idle_resources.append(msg)
                    self.recommendations.append(
                        f"Release idle EIP {eip['PublicIp']} ({region}) — saves ~$3.65/mo"
                    )

            # ── Stopped instances (EBS still billing)
            for r in ec2.describe_instances(
                Filters=[{"Name": "instance-state-name", "Values": ["stopped"]}]
            )["Reservations"]:
                for i in r["Instances"]:
                    name = next(
                        (t["Value"] for t in i.get("Tags", []) if t["Key"] == "Name"),
                        i["InstanceId"],
                    )
                    for blk in i.get("BlockDeviceMappings", []):
                        vol_id = blk["Ebs"]["VolumeId"]
                        try:
                            vol = ec2.describe_volumes(VolumeIds=[vol_id])["Volumes"][0]
                            monthly = round(vol["Size"] * 0.08, 2)
                            msg = (
                                f"Stopped instance {name} ({i['InstanceId']}) in {region} "
                                f"— {vol['Size']}GB {vol['VolumeType']} still billing (~${monthly}/mo)"
                            )
                            warn(msg)
                            self.idle_resources.append(msg)
                            self.recommendations.append(
                                f"Terminate stopped instance {name} ({i['InstanceId']}) in {region} "
                                f"if unused — saves ~${monthly}/mo on EBS"
                            )
                        except ClientError:
                            pass

            # ── Unattached EBS volumes
            for vol in ec2.describe_volumes(
                Filters=[{"Name": "status", "Values": ["available"]}]
            )["Volumes"]:
                monthly = round(vol["Size"] * 0.08, 2)
                msg = (
                    f"Unattached {vol['Size']}GB {vol['VolumeType']} volume "
                    f"{vol['VolumeId']} in {region} (~${monthly}/mo)"
                )
                warn(msg)
                self.idle_resources.append(msg)
                self.recommendations.append(
                    f"Delete or snapshot unattached volume {vol['VolumeId']} ({region}) — saves ~${monthly}/mo"
                )

            # ── Load balancers with no healthy targets
            elbv2 = session.client("elbv2", region_name=region)
            for lb in elbv2.describe_load_balancers()["LoadBalancers"]:
                tgs = elbv2.describe_target_groups(
                    LoadBalancerArn=lb["LoadBalancerArn"]
                )["TargetGroups"]
                healthy = 0
                for tg in tgs:
                    try:
                        health = elbv2.describe_target_health(
                            TargetGroupArn=tg["TargetGroupArn"]
                        )
                        healthy += sum(
                            1 for t in health["TargetHealthDescriptions"]
                            if t["TargetHealth"]["State"] == "healthy"
                        )
                    except ClientError:
                        pass
                if healthy == 0:
                    msg = f"LB {lb['LoadBalancerName']} in {region} has no healthy targets (~$16/mo)"
                    warn(msg)
                    self.idle_resources.append(msg)
                    self.recommendations.append(
                        f"Delete idle LB {lb['LoadBalancerName']} ({region}) — saves ~$16/mo"
                    )

            # ── NAT Gateways (informational — they're expensive)
            for nat in ec2.describe_nat_gateways(
                Filters=[{"Name": "state", "Values": ["available"]}]
            )["NatGateways"]:
                msg = f"NAT Gateway {nat['NatGatewayId']} running in {region} (~$32/mo base + data)"
                info(msg)
                self.recommendations.append(
                    f"NAT Gateway {nat['NatGatewayId']} ({region}): use VPC endpoints for S3/DynamoDB "
                    f"to reduce data processing charges"
                )

        except ClientError:
            pass  # Region not enabled or no access

    # ──────────────────────────────────────────────────────────
    # PHASE 4 — Recommendations
    # ──────────────────────────────────────────────────────────
    def print_recommendations(self):
        section("PHASE 4: COST REDUCTION RECOMMENDATIONS")

        # Service-specific recommendations based on top spenders
        days_elapsed = date.today().day
        for service, amt in self.top_services[:6]:
            run_rate = amt * 30 / days_elapsed  # extrapolate to full month

            if "Elastic Load Balancing" in service and run_rate > 5:
                self.recommendations.append(
                    f"ELB ~${run_rate:.0f}/mo: check for idle LBs; "
                    f"delete any with no targets"
                )
            if "Virtual Private Cloud" in service and run_rate > 5:
                self.recommendations.append(
                    f"VPC/NAT ~${run_rate:.0f}/mo: consolidate NAT Gateways; "
                    f"add VPC endpoints for S3 and DynamoDB to cut data processing fees"
                )
            if "Elastic Compute Cloud" in service and run_rate > 10:
                self.recommendations.append(
                    f"EC2 ~${run_rate:.0f}/mo: rightsize instances; "
                    f"consider Reserved Instances or Savings Plans for steady workloads (up to 40% savings)"
                )
            if "Simple Storage" in service and run_rate > 5:
                self.recommendations.append(
                    f"S3 ~${run_rate:.0f}/mo: enable lifecycle policies to move old data to Glacier; "
                    f"audit buckets for stale large objects"
                )
            if "Elastic Cloud" in service or "Elasticsearch" in service:
                self.recommendations.append(
                    f"Elasticsearch ~${run_rate:.0f}/mo: implement ILM hot/warm/cold tiers; "
                    f"reduce replicas on old indices; annual commitment saves 30-40%"
                )
            if "Relational Database" in service and run_rate > 10:
                self.recommendations.append(
                    f"RDS ~${run_rate:.0f}/mo: check for multi-AZ on non-prod; "
                    f"consider Aurora Serverless for variable workloads"
                )

        if not self.recommendations:
            ok("No major cost reduction opportunities identified")
            return

        for i, rec in enumerate(self.recommendations, 1):
            print(f"  {i:2d}. {rec}")

    # ──────────────────────────────────────────────────────────
    # PHASE 5 — Monitoring Setup
    # ──────────────────────────────────────────────────────────
    def setup_monitoring(self):
        section("PHASE 5: MONITORING SETUP")

        budgets_client = self.session.client("budgets")
        ce_client      = self.session.client("ce")
        target_account = self.management_id if self.is_management else self.account_id

        info(f"Target account:  {target_account}")
        info(f"Alert email:     {self.alert_email}")
        info(f"Monthly budget:  ${self.budget_limit:.2f}")
        print()

        # ── Org-wide monthly budget
        self._ensure_budget(
            budgets_client,
            account_id=target_account,
            name=f"Org Monthly Budget - {target_account}",
            limit=self.budget_limit,
            cost_filters={},
            thresholds=[50, 80, 100],
        )

        # ── Per-service anomaly monitor (org-wide)
        svc_monitor_arn = self._ensure_anomaly_monitor(
            ce_client,
            name="Org-Wide Per-Service Anomaly Monitor",
            monitor_type="DIMENSIONAL",
            dimension="SERVICE",
        )
        if svc_monitor_arn:
            self._ensure_anomaly_subscription(
                ce_client,
                name="Org-Wide Service Anomaly Alerts",
                monitor_arn=svc_monitor_arn,
                threshold=ANOMALY_THRESHOLD,
            )

        # ── Per-account monitors for top spenders (multi-account only)
        if self.is_management and self.is_org and len(self.top_accounts) > 0:
            id_to_name = {a["Id"]: a["Name"] for a in self.org_accounts}
            sub("Per-Account Anomaly Monitors (top spenders)")
            for acct_id, amt in self.top_accounts[:3]:
                name = id_to_name.get(acct_id, acct_id)
                monitor_arn = self._ensure_anomaly_monitor(
                    ce_client,
                    name=f"Account Monitor - {name}",
                    monitor_type="CUSTOM",
                    account_id=acct_id,
                )
                if monitor_arn:
                    self._ensure_anomaly_subscription(
                        ce_client,
                        name=f"Anomaly Alerts - {name}",
                        monitor_arn=monitor_arn,
                        threshold=ANOMALY_THRESHOLD,
                    )

        print()
        section("SETUP COMPLETE")
        ok(f"All alerts → {self.alert_email}")
        ok(f"Monthly budget: ${self.budget_limit:.2f}  (alerts at 50%, 80%, 100% + forecast)")
        ok(f"Anomaly detection: alert when impact ≥ ${ANOMALY_THRESHOLD}")
        info("View in AWS Console → Cost Explorer → Anomaly Detection → Alert subscriptions")

    # ── Helpers ────────────────────────────────────────────────

    def _ensure_budget(self, client, account_id, name, limit, cost_filters, thresholds):
        try:
            existing = client.describe_budgets(AccountId=account_id)
            if any(b["BudgetName"] == name for b in existing.get("Budgets", [])):
                ok(f"Budget already exists: '{name}'")
                return
        except ClientError:
            pass

        budget_def = {
            "BudgetName": name,
            "BudgetType": "COST",
            "TimeUnit": "MONTHLY",
            "BudgetLimit": {"Amount": str(limit), "Unit": "USD"},
            "CostTypes": {
                "IncludeTax": False,
                "IncludeSubscription": True,
                "UseBlended": False,
                "IncludeRefund": False,
                "IncludeCredit": False,
                "IncludeUpfront": True,
                "IncludeRecurring": True,
                "IncludeOtherSubscription": True,
                "IncludeSupport": False,
                "IncludeDiscount": True,
                "UseAmortized": False,
            },
        }
        if cost_filters:
            budget_def["CostFilters"] = cost_filters

        notifications = [
            {
                "Notification": {
                    "NotificationType": "ACTUAL",
                    "ComparisonOperator": "GREATER_THAN",
                    "Threshold": float(t),
                    "ThresholdType": "PERCENTAGE",
                },
                "Subscribers": [{"SubscriptionType": "EMAIL", "Address": self.alert_email}],
            }
            for t in thresholds
        ]
        notifications.append(
            {
                "Notification": {
                    "NotificationType": "FORECASTED",
                    "ComparisonOperator": "GREATER_THAN",
                    "Threshold": 100.0,
                    "ThresholdType": "PERCENTAGE",
                },
                "Subscribers": [{"SubscriptionType": "EMAIL", "Address": self.alert_email}],
            }
        )

        try:
            client.create_budget(
                AccountId=account_id,
                Budget=budget_def,
                NotificationsWithSubscribers=notifications,
            )
            ok(f"Created budget: '{name}'  (${limit}/mo, alerts at {thresholds}% + forecast)")
        except ClientError as e:
            err(f"Budget '{name}': {e}")

    def _ensure_anomaly_monitor(
        self, ce_client, name, monitor_type, dimension=None, account_id=None
    ):
        try:
            monitors = ce_client.get_anomaly_monitors()["AnomalyMonitors"]
            for m in monitors:
                if m["MonitorName"] == name:
                    ok(f"Anomaly monitor already exists: '{name}'")
                    return m["MonitorArn"]
        except ClientError:
            pass

        monitor_def = {"MonitorName": name, "MonitorType": monitor_type}
        if monitor_type == "DIMENSIONAL" and dimension:
            monitor_def["MonitorDimension"] = dimension
        elif monitor_type == "CUSTOM" and account_id:
            monitor_def["MonitorSpecification"] = {
                "Dimensions": {
                    "Key": "LINKED_ACCOUNT",
                    "Values": [account_id],
                    "MatchOptions": ["EQUALS"],
                }
            }

        try:
            resp = ce_client.create_anomaly_monitor(AnomalyMonitor=monitor_def)
            ok(f"Created anomaly monitor: '{name}'")
            return resp["MonitorArn"]
        except ClientError as e:
            err(f"Monitor '{name}': {e}")
            return None

    def _ensure_anomaly_subscription(self, ce_client, name, monitor_arn, threshold):
        try:
            subs = ce_client.get_anomaly_subscriptions()["AnomalySubscriptions"]
            if any(s["SubscriptionName"] == name for s in subs):
                ok(f"Subscription already exists: '{name}'")
                return
        except ClientError:
            pass

        try:
            ce_client.create_anomaly_subscription(
                AnomalySubscription={
                    "SubscriptionName": name,
                    "MonitorArnList": [monitor_arn],
                    "Subscribers": [{"Address": self.alert_email, "Type": "EMAIL"}],
                    "Frequency": "DAILY",
                    "ThresholdExpression": {
                        "Dimensions": {
                            "Key": "ANOMALY_TOTAL_IMPACT_ABSOLUTE",
                            "Values": [str(threshold)],
                            "MatchOptions": ["GREATER_THAN_OR_EQUAL"],
                        }
                    },
                }
            )
            ok(f"Created subscription: '{name}'  → {self.alert_email}")
        except ClientError as e:
            err(f"Subscription '{name}': {e}")


# ══════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(
        description="AWS Cost Analyzer & Monitor Setup",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full analysis + monitoring setup
  python3 aws_cost_analyzer.py --profile jojo-aws-management --email ops@example.com --budget 100

  # Analysis only, no changes
  python3 aws_cost_analyzer.py --profile my-profile --email me@example.com --skip-monitoring
        """,
    )
    parser.add_argument("--profile",          required=True,  help="AWS CLI profile name")
    parser.add_argument("--email",            required=True,  help="Email for all cost alerts")
    parser.add_argument("--budget",           type=float,     default=DEFAULT_BUDGET,
                        help=f"Monthly budget limit in USD (default: {DEFAULT_BUDGET})")
    parser.add_argument("--skip-monitoring",  action="store_true",
                        help="Run analysis only — skip budget and monitor creation")
    args = parser.parse_args()

    print(f"\n{'─'*62}")
    print(f"  AWS Cost Analyzer & Monitor Setup")
    print(f"  Profile : {args.profile}")
    print(f"  Email   : {args.email}")
    print(f"  Budget  : ${args.budget:.2f}/mo")
    print(f"{'─'*62}")

    analyzer = AWSCostAnalyzer(
        profile=args.profile,
        alert_email=args.email,
        budget_limit=args.budget,
    )

    analyzer.detect_structure()
    analyzer.analyze_costs()
    analyzer.detect_idle_resources()
    analyzer.print_recommendations()

    if not args.skip_monitoring:
        analyzer.setup_monitoring()


if __name__ == "__main__":
    main()
