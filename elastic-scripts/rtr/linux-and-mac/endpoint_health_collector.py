#!/usr/bin/env python3
"""
Endpoint Health Collector — Elastic Security Script Library
Runs ON the endpoint via Run Script response action.
Output is captured by Elastic Defend and returned to Kibana.
Compatible: macOS, Linux | Requires: Python 3.6+ stdlib only
"""

import json, platform, subprocess, datetime, os, pwd, socket, re, sys
from pathlib import Path

SECTION = lambda title: print(f"\n{'='*60}\n  {title}\n{'='*60}")
CMD     = lambda args: subprocess.run(args, capture_output=True, text=True, timeout=10).stdout.strip()

report = {"generated_at": datetime.datetime.utcnow().isoformat() + "Z", "sections": {}}
IS_MAC = platform.system() == "Darwin"


# ── 1. SYSTEM INFO ────────────────────────────────────────────
def system_info():
    info = {
        "hostname":   socket.gethostname(),
        "fqdn":       socket.getfqdn(),
        "os":         platform.platform(),
        "os_version": platform.version(),
        "arch":       platform.machine(),
        "python":     platform.python_version(),
        "uptime":     CMD(["uptime"]),
        "boot_time":  CMD(["sysctl", "-n", "kern.boottime"]) if IS_MAC else CMD(["uptime", "-s"]),
    }
    if IS_MAC:
        info["hw_model"] = CMD(["sysctl", "-n", "hw.model"])
        info["cpu"]      = CMD(["sysctl", "-n", "machdep.cpu.brand_string"])
        info["ram_gb"]   = str(round(int(CMD(["sysctl", "-n", "hw.memsize"])) / 1e9, 1)) + " GB"
        info["serial"]   = CMD(["system_profiler", "SPHardwareDataType"]).split("Serial Number (system):")[1].split()[0] if "Serial Number" in CMD(["system_profiler", "SPHardwareDataType"]) else "N/A"
    report["sections"]["system_info"] = info
    SECTION("SYSTEM INFO")
    for k, v in info.items():
        print(f"  {k:<15} {v}")


# ── 2. LOGGED-IN USERS ────────────────────────────────────────
def logged_in_users():
    raw = CMD(["who"])
    users = []
    for line in raw.splitlines():
        parts = line.split()
        if parts:
            users.append({"user": parts[0], "tty": parts[1] if len(parts) > 1 else "", "since": " ".join(parts[2:4]) if len(parts) > 3 else ""})
    report["sections"]["logged_in_users"] = users
    SECTION("LOGGED-IN USERS")
    if users:
        for u in users:
            print(f"  {u['user']:<15} {u['tty']:<10} since {u['since']}")
    else:
        print("  No active user sessions")


# ── 3. RECENT LOGINS ──────────────────────────────────────────
def recent_logins():
    raw = CMD(["last", "-20"])
    lines = [l for l in raw.splitlines() if l.strip() and "wtmp" not in l][:15]
    report["sections"]["recent_logins"] = lines
    SECTION("RECENT LOGINS (last 15)")
    for line in lines:
        print(f"  {line}")


# ── 4. TOP PROCESSES ──────────────────────────────────────────
def top_processes():
    if IS_MAC:
        raw = CMD(["ps", "aux", "-r"])
    else:
        raw = CMD(["ps", "aux", "--sort=-%cpu"])

    lines  = raw.splitlines()
    header = lines[0] if lines else ""
    procs  = []
    for line in lines[1:21]:
        parts = line.split(None, 10)
        if len(parts) >= 11:
            procs.append({
                "user":    parts[0],
                "pid":     parts[1],
                "cpu_pct": parts[2],
                "mem_pct": parts[3],
                "command": parts[10][:80]
            })

    report["sections"]["top_processes_by_cpu"] = procs
    SECTION("TOP 20 PROCESSES (by CPU)")
    print(f"  {'USER':<12} {'PID':<7} {'%CPU':<6} {'%MEM':<6} COMMAND")
    print(f"  {'-'*70}")
    for p in procs:
        print(f"  {p['user']:<12} {p['pid']:<7} {p['cpu_pct']:<6} {p['mem_pct']:<6} {p['command']}")


# ── 5. NETWORK CONNECTIONS ────────────────────────────────────
def network_connections():
    raw  = CMD(["netstat", "-an", "-p", "tcp"]) if IS_MAC else CMD(["ss", "-tnp"])
    established = [l for l in raw.splitlines() if "ESTABLISHED" in l]
    listening   = [l for l in raw.splitlines() if "LISTEN" in l]

    report["sections"]["network"] = {
        "established_count": len(established),
        "listening_count":   len(listening),
        "established":       established[:20],
        "listening":         listening[:20]
    }

    SECTION("NETWORK CONNECTIONS")
    print(f"  Established : {len(established)}")
    print(f"  Listening   : {len(listening)}")
    print(f"\n  {'ESTABLISHED CONNECTIONS':}")
    for line in established[:15]:
        print(f"  {line}")
    print(f"\n  {'LISTENING PORTS':}")
    for line in listening[:15]:
        print(f"  {line}")


# ── 6. PERSISTENCE MECHANISMS (macOS) ────────────────────────
def persistence_checks():
    items = []

    if IS_MAC:
        launch_dirs = [
            "/Library/LaunchDaemons",
            "/Library/LaunchAgents",
            Path.home() / "Library/LaunchAgents",
            "/System/Library/LaunchDaemons",
        ]
        for d in launch_dirs:
            try:
                plists = list(Path(d).glob("*.plist"))
                for p in plists:
                    items.append({"type": "LaunchAgent/Daemon", "path": str(p), "dir": str(d)})
            except Exception:
                pass

        # Login items
        login_raw = CMD(["osascript", "-e", 'tell application "System Events" to get the name of every login item'])
        if login_raw:
            for item in login_raw.split(", "):
                items.append({"type": "LoginItem", "path": item.strip()})

        # Cron jobs
        cron_raw = CMD(["crontab", "-l"])
        if cron_raw and "no crontab" not in cron_raw.lower():
            for line in cron_raw.splitlines():
                if not line.startswith("#"):
                    items.append({"type": "cron", "path": line})
    else:
        cron_raw = CMD(["crontab", "-l"])
        if cron_raw:
            for line in cron_raw.splitlines():
                if not line.startswith("#"):
                    items.append({"type": "cron", "path": line})
        for svc in Path("/etc/systemd/system").glob("*.service") if Path("/etc/systemd/system").exists() else []:
            items.append({"type": "systemd", "path": str(svc)})

    report["sections"]["persistence"] = items
    SECTION("PERSISTENCE MECHANISMS")
    print(f"  Total items found: {len(items)}")
    for item in items[:30]:
        print(f"  [{item['type']:<20}] {item['path']}")


# ── 7. SECURITY POSTURE (macOS) ───────────────────────────────
def security_posture():
    posture = {}

    if IS_MAC:
        posture["SIP_status"]       = CMD(["csrutil", "status"])
        posture["firewall_status"]  = CMD(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
        posture["gatekeeper"]       = CMD(["spctl", "--status"])
        posture["filevault"]        = CMD(["fdesetup", "status"])
        posture["XProtect_version"] = CMD(["system_profiler", "SPInstallHistoryDataType"]).split("XProtect")[1].split("\n")[1].strip() if "XProtect" in CMD(["system_profiler", "SPInstallHistoryDataType"]) else "N/A"
        posture["ssh_service"]      = "running" if "com.openssh.sshd" in CMD(["launchctl", "list"]) else "stopped"
        posture["remote_login"]     = CMD(["systemsetup", "-getremotelogin"])
        posture["screen_sharing"]   = "enabled" if "screensharing" in CMD(["launchctl", "list"]).lower() else "disabled"

    report["sections"]["security_posture"] = posture
    SECTION("SECURITY POSTURE")
    for k, v in posture.items():
        flag = "  [!]" if any(x in str(v).lower() for x in ["disabled", "off", "stopped"]) else "  [+]"
        print(f"{flag} {k:<25} {v}")


# ── 8. RECENTLY MODIFIED FILES ────────────────────────────────
def recent_file_changes():
    watch_dirs = ["/tmp", "/var/tmp", str(Path.home() / "Downloads"), "/usr/local/bin"]
    if not IS_MAC:
        watch_dirs += ["/tmp", "/var/tmp"]

    findings = []
    for d in watch_dirs:
        try:
            raw = CMD(["find", d, "-maxdepth", "2", "-newer", "/etc/passwd", "-type", "f"])
            for f in raw.splitlines():
                if f.strip():
                    findings.append({"dir": d, "file": f.strip()})
        except Exception:
            pass

    report["sections"]["recent_file_changes"] = findings
    SECTION("RECENTLY MODIFIED FILES (key dirs)")
    if findings:
        for f in findings[:25]:
            print(f"  {f['file']}")
    else:
        print("  No recent modifications detected")


# ── 9. DISK USAGE ─────────────────────────────────────────────
def disk_usage():
    raw = CMD(["df", "-h"])
    lines = [l for l in raw.splitlines() if not l.startswith("map") and not l.startswith("devfs")]
    report["sections"]["disk_usage"] = lines
    SECTION("DISK USAGE")
    for line in lines:
        print(f"  {line}")


# ── MAIN ──────────────────────────────────────────────────────
if __name__ == "__main__":
    print(f"Elastic Endpoint Health Collector")
    print(f"Run at : {report['generated_at']}")
    print(f"Host   : {socket.gethostname()}")

    for fn in [system_info, logged_in_users, recent_logins, top_processes,
               network_connections, persistence_checks, security_posture,
               recent_file_changes, disk_usage]:
        try:
            fn()
        except Exception as e:
            print(f"\n[ERROR in {fn.__name__}]: {e}")

    SECTION("JSON SUMMARY")
    print(json.dumps(report, indent=2, default=str))
