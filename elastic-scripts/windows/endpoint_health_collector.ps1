#Requires -Version 5.1
<#
.SYNOPSIS
    Endpoint Health Collector - Elastic Security Script Library
    Runs ON the endpoint via Run Script response action.
    Output is captured by Elastic Defend and returned to Kibana.
    Compatible: Windows 10/11, Windows Server 2016+
#>

$ErrorActionPreference = "SilentlyContinue"
$report = @{ generated_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"); sections = @{} }

function Write-Section($title) {
    Write-Output "`n$("="*60)`n  $title`n$("="*60)"
}


# ── 1. SYSTEM INFO ────────────────────────────────────────────
function Get-SystemInfo {
    $os   = Get-CimInstance Win32_OperatingSystem
    $cs   = Get-CimInstance Win32_ComputerSystem
    $bios = Get-CimInstance Win32_BIOS
    $cpu  = Get-CimInstance Win32_Processor | Select-Object -First 1

    $uptime = (Get-Date) - $os.LastBootUpTime

    $info = @{
        hostname       = $env:COMPUTERNAME
        fqdn           = [System.Net.Dns]::GetHostEntry("").HostName
        os             = $os.Caption
        os_version     = $os.Version
        os_build       = $os.BuildNumber
        arch           = $os.OSArchitecture
        install_date   = $os.InstallDate.ToString("yyyy-MM-dd")
        boot_time      = $os.LastBootUpTime.ToString("yyyy-MM-dd HH:mm:ss")
        uptime         = "$($uptime.Days)d $($uptime.Hours)h $($uptime.Minutes)m"
        ram_gb         = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
        cpu            = $cpu.Name
        cpu_cores      = $cpu.NumberOfCores
        manufacturer   = $cs.Manufacturer
        model          = $cs.Model
        serial         = $bios.SerialNumber
        domain         = $cs.Domain
        powershell_ver = $PSVersionTable.PSVersion.ToString()
    }

    $report.sections["system_info"] = $info
    Write-Section "SYSTEM INFO"
    $info.GetEnumerator() | Sort-Object Key | ForEach-Object {
        Write-Output ("  {0,-20} {1}" -f $_.Key, $_.Value)
    }
}


# ── 2. LOGGED-IN USERS ────────────────────────────────────────
function Get-LoggedInUsers {
    $sessions = query user 2>$null
    $users = @()

    if ($sessions) {
        $sessions | Select-Object -Skip 1 | ForEach-Object {
            $parts = $_ -split '\s+' | Where-Object { $_ -ne "" }
            if ($parts.Count -ge 4) {
                $users += @{
                    user    = $parts[0] -replace '^>', ''
                    session = $parts[1]
                    id      = $parts[2]
                    state   = $parts[3]
                    logon   = if ($parts.Count -ge 6) { "$($parts[4]) $($parts[5])" } else { "N/A" }
                }
            }
        }
    }

    $report.sections["logged_in_users"] = $users
    Write-Section "LOGGED-IN USERS"
    if ($users.Count -gt 0) {
        Write-Output ("  {0,-20} {1,-12} {2,-8} {3,-10} {4}" -f "USER","SESSION","ID","STATE","LOGON TIME")
        Write-Output "  $("-"*70)"
        $users | ForEach-Object {
            Write-Output ("  {0,-20} {1,-12} {2,-8} {3,-10} {4}" -f $_["user"],$_["session"],$_["id"],$_["state"],$_["logon"])
        }
    } else {
        Write-Output "  No active user sessions"
    }
}


# ── 3. RECENT LOGINS ──────────────────────────────────────────
function Get-RecentLogins {
    $events = Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4624]]" -MaxEvents 20 |
        Select-Object TimeCreated,
            @{N="User";    E={ $_.Properties[5].Value }},
            @{N="Domain";  E={ $_.Properties[6].Value }},
            @{N="LogonType";E={ $_.Properties[8].Value }},
            @{N="Source";  E={ $_.Properties[18].Value }}

    $logonTypes = @{2="Interactive";3="Network";4="Batch";5="Service";7="Unlock";10="RemoteInteractive";11="CachedInteractive"}
    $logins = @()

    $events | ForEach-Object {
        $logins += @{
            time       = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            user       = "$($_.Domain)\$($_.User)"
            logon_type = $logonTypes[[int]$_.LogonType]
            source_ip  = $_.Source
        }
    }

    $report.sections["recent_logins"] = $logins
    Write-Section "RECENT LOGINS (last 20)"
    Write-Output ("  {0,-22} {1,-30} {2,-18} {3}" -f "TIME","USER","TYPE","SOURCE IP")
    Write-Output "  $("-"*80)"
    $logins | ForEach-Object {
        Write-Output ("  {0,-22} {1,-30} {2,-18} {3}" -f $_["time"],$_["user"],$_["logon_type"],$_["source_ip"])
    }
}


# ── 4. TOP PROCESSES ──────────────────────────────────────────
function Get-TopProcesses {
    $procs = Get-Process | Sort-Object CPU -Descending | Select-Object -First 25 |
        Select-Object Name, Id,
            @{N="CPU_s";    E={ [math]::Round($_.CPU, 1) }},
            @{N="RAM_MB";   E={ [math]::Round($_.WorkingSet64 / 1MB, 1) }},
            @{N="Threads";  E={ $_.Threads.Count }},
            @{N="Path";     E={ try { $_.MainModule.FileName } catch { "N/A" } }}

    $report.sections["top_processes"] = $procs
    Write-Section "TOP 25 PROCESSES (by CPU time)"
    Write-Output ("  {0,-30} {1,-8} {2,-10} {3,-10} {4,-8} {5}" -f "NAME","PID","CPU(s)","RAM(MB)","THREADS","PATH")
    Write-Output "  $("-"*100)"
    $procs | ForEach-Object {
        Write-Output ("  {0,-30} {1,-8} {2,-10} {3,-10} {4,-8} {5}" -f $_.Name,$_.Id,$_.CPU_s,$_.RAM_MB,$_.Threads,($_.Path -replace '.{0,60}$', { $_.Value.Substring([Math]::Max(0,$_.Value.Length-60)) }))
    }
}


# ── 5. NETWORK CONNECTIONS ────────────────────────────────────
function Get-NetworkConnections {
    $conns = Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State,
        @{N="PID";     E={ $_.OwningProcess }},
        @{N="Process"; E={ try { (Get-Process -Id $_.OwningProcess).Name } catch { "N/A" } }}

    $established = $conns | Where-Object { $_.State -eq "Established" }
    $listening   = $conns | Where-Object { $_.State -eq "Listen" }

    $report.sections["network"] = @{
        established_count = $established.Count
        listening_count   = $listening.Count
    }

    Write-Section "NETWORK CONNECTIONS"
    Write-Output "  Established : $($established.Count)"
    Write-Output "  Listening   : $($listening.Count)"

    Write-Output "`n  ESTABLISHED CONNECTIONS"
    Write-Output ("  {0,-16} {1,-7} {2,-16} {3,-7} {4,-8} {5}" -f "LOCAL IP","L.PORT","REMOTE IP","R.PORT","PID","PROCESS")
    Write-Output "  $("-"*80)"
    $established | Select-Object -First 20 | ForEach-Object {
        Write-Output ("  {0,-16} {1,-7} {2,-16} {3,-7} {4,-8} {5}" -f $_.LocalAddress,$_.LocalPort,$_.RemoteAddress,$_.RemotePort,$_.PID,$_.Process)
    }

    Write-Output "`n  LISTENING PORTS"
    Write-Output ("  {0,-16} {1,-7} {2,-8} {3}" -f "LOCAL IP","PORT","PID","PROCESS")
    Write-Output "  $("-"*50)"
    $listening | Sort-Object LocalPort | Select-Object -First 20 | ForEach-Object {
        Write-Output ("  {0,-16} {1,-7} {2,-8} {3}" -f $_.LocalAddress,$_.LocalPort,$_.PID,$_.Process)
    }
}


# ── 6. PERSISTENCE MECHANISMS ─────────────────────────────────
function Get-PersistenceMechanisms {
    $items = @()

    # Registry run keys
    $runKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
    )
    foreach ($key in $runKeys) {
        $vals = Get-ItemProperty -Path $key
        if ($vals) {
            $vals.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                $items += @{ type = "Registry Run Key"; location = $key; name = $_.Name; value = $_.Value }
            }
        }
    }

    # Scheduled tasks
    $tasks = Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" } | Select-Object -First 30
    $tasks | ForEach-Object {
        $action = ($_.Actions | Select-Object -First 1)
        $items += @{
            type     = "Scheduled Task"
            location = $_.TaskPath
            name     = $_.TaskName
            value    = "$($action.Execute) $($action.Arguments)"
        }
    }

    # Services set to auto-start (non-Microsoft)
    Get-CimInstance Win32_Service | Where-Object {
        $_.StartMode -eq "Auto" -and $_.State -eq "Running" -and $_.PathName -notmatch "system32|syswow64"
    } | Select-Object -First 20 | ForEach-Object {
        $items += @{ type = "Auto Service"; location = "Services"; name = $_.Name; value = $_.PathName }
    }

    # Startup folder
    $startupFolders = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    foreach ($folder in $startupFolders) {
        if (Test-Path $folder) {
            Get-ChildItem $folder | ForEach-Object {
                $items += @{ type = "Startup Folder"; location = $folder; name = $_.Name; value = $_.FullName }
            }
        }
    }

    $report.sections["persistence"] = $items
    Write-Section "PERSISTENCE MECHANISMS"
    Write-Output "  Total items: $($items.Count)"
    Write-Output ("  {0,-20} {1,-35} {2}" -f "TYPE","NAME","VALUE")
    Write-Output "  $("-"*90)"
    $items | ForEach-Object {
        $val = if ($_["value"].Length -gt 60) { $_["value"].Substring(0,60) + "..." } else { $_["value"] }
        Write-Output ("  {0,-20} {1,-35} {2}" -f $_["type"],$_["name"],$val)
    }
}


# ── 7. SECURITY POSTURE ───────────────────────────────────────
function Get-SecurityPosture {
    $posture = @{}

    # Windows Defender
    $defender = Get-MpComputerStatus
    if ($defender) {
        $posture["AV_enabled"]           = $defender.AntivirusEnabled
        $posture["AV_signatures_date"]   = $defender.AntivirusSignatureLastUpdated.ToString("yyyy-MM-dd")
        $posture["realtime_protection"]  = $defender.RealTimeProtectionEnabled
        $posture["tamper_protection"]    = $defender.IsTamperProtected
        $posture["behavior_monitor"]     = $defender.BehaviorMonitorEnabled
    }

    # Firewall
    $fw = Get-NetFirewallProfile | Select-Object Name, Enabled
    $fw | ForEach-Object { $posture["firewall_$($_.Name)"] = $_.Enabled }

    # UAC
    $uac = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System").EnableLUA
    $posture["UAC_enabled"] = [bool]$uac

    # BitLocker
    $bl = Get-BitLockerVolume -MountPoint "C:" 2>$null
    $posture["bitlocker_status"] = if ($bl) { $bl.ProtectionStatus } else { "N/A" }

    # Auto updates
    $au = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ErrorAction SilentlyContinue).NoAutoUpdate
    $posture["auto_updates_disabled"] = [bool]$au

    # RDP
    $rdp = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server").fDenyTSConnections
    $posture["RDP_enabled"] = ($rdp -eq 0)

    # Last patch date
    $lastPatch = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
    $posture["last_patch"] = if ($lastPatch.InstalledOn) { $lastPatch.InstalledOn.ToString("yyyy-MM-dd") } else { "N/A" }
    $posture["last_patch_kb"] = $lastPatch.HotFixID

    $report.sections["security_posture"] = $posture
    Write-Section "SECURITY POSTURE"
    $posture.GetEnumerator() | Sort-Object Key | ForEach-Object {
        $flag = if ($_.Value -eq $false -or $_.Value -eq "Off" -or $_.Value -eq "Unprotected") { "  [!]" } else { "  [+]" }
        Write-Output ("{0} {1,-35} {2}" -f $flag, $_.Key, $_.Value)
    }
}


# ── 8. RECENTLY MODIFIED FILES ────────────────────────────────
function Get-RecentFileChanges {
    $watchDirs = @($env:TEMP, "$env:USERPROFILE\Downloads", "C:\Windows\Temp", "C:\Users\Public")
    $cutoff    = (Get-Date).AddHours(-24)
    $findings  = @()

    foreach ($dir in $watchDirs) {
        if (Test-Path $dir) {
            Get-ChildItem $dir -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -gt $cutoff -and !$_.PSIsContainer } |
                Select-Object -First 15 | ForEach-Object {
                    $findings += @{ dir = $dir; file = $_.FullName; modified = $_.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss"); size_kb = [math]::Round($_.Length/1KB,1) }
                }
        }
    }

    $report.sections["recent_file_changes"] = $findings
    Write-Section "RECENTLY MODIFIED FILES (last 24h, key dirs)"
    if ($findings.Count -gt 0) {
        Write-Output ("  {0,-22} {1,-10} {2}" -f "MODIFIED","SIZE(KB)","FILE")
        Write-Output "  $("-"*80)"
        $findings | ForEach-Object {
            Write-Output ("  {0,-22} {1,-10} {2}" -f $_["modified"],$_["size_kb"],$_["file"])
        }
    } else {
        Write-Output "  No recent modifications detected"
    }
}


# ── 9. DISK USAGE ─────────────────────────────────────────────
function Get-DiskUsage {
    $disks = Get-PSDrive -PSProvider FileSystem | Select-Object Name,
        @{N="Used_GB";  E={ [math]::Round(($_.Used)/1GB, 1) }},
        @{N="Free_GB";  E={ [math]::Round(($_.Free)/1GB, 1) }},
        @{N="Total_GB"; E={ [math]::Round(($_.Used + $_.Free)/1GB, 1) }},
        @{N="Pct_Used"; E={ if (($_.Used + $_.Free) -gt 0) { [math]::Round($_.Used / ($_.Used + $_.Free) * 100, 1) } else { 0 } }},
        Root

    $report.sections["disk_usage"] = $disks
    Write-Section "DISK USAGE"
    Write-Output ("  {0,-6} {1,-10} {2,-10} {3,-10} {4,-10} {5}" -f "DRIVE","USED(GB)","FREE(GB)","TOTAL(GB)","% USED","ROOT")
    Write-Output "  $("-"*65)"
    $disks | ForEach-Object {
        $flag = if ($_.Pct_Used -gt 85) { " [!]" } else { "    " }
        Write-Output ("  {0,-6} {1,-10} {2,-10} {3,-10} {4,-10} {5}{6}" -f $_.Name,$_.Used_GB,$_.Free_GB,$_.Total_GB,$_.Pct_Used,$_.Root,$flag)
    }
}


# ── 10. LOCAL ADMIN ACCOUNTS ──────────────────────────────────
function Get-LocalAdmins {
    $admins = @()
    try {
        $group = [ADSI]"WinNT://./Administrators,group"
        $group.Members() | ForEach-Object {
            $ads = [ADSI]$_
            $admins += @{ name = $ads.Name[0]; path = $ads.Path }
        }
    } catch {
        $admins = Get-LocalGroupMember -Group "Administrators" | Select-Object Name, ObjectClass, PrincipalSource |
            ForEach-Object { @{ name = $_.Name; type = $_.ObjectClass; source = $_.PrincipalSource } }
    }

    $report.sections["local_admins"] = $admins
    Write-Section "LOCAL ADMINISTRATOR ACCOUNTS"
    $admins | ForEach-Object { Write-Output "  [ADMIN] $($_['name'])" }
}


# ── MAIN ──────────────────────────────────────────────────────
Write-Output "Elastic Endpoint Health Collector (PowerShell)"
Write-Output "Run at : $($report.generated_at)"
Write-Output "Host   : $env:COMPUTERNAME"

$functions = @(
    { Get-SystemInfo },
    { Get-LoggedInUsers },
    { Get-RecentLogins },
    { Get-TopProcesses },
    { Get-NetworkConnections },
    { Get-PersistenceMechanisms },
    { Get-SecurityPosture },
    { Get-RecentFileChanges },
    { Get-DiskUsage },
    { Get-LocalAdmins }
)

foreach ($fn in $functions) {
    try { & $fn }
    catch { Write-Output "`n[ERROR]: $_" }
}

Write-Section "JSON SUMMARY"
$report | ConvertTo-Json -Depth 6 -Compress
