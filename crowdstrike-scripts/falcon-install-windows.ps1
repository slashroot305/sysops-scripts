<#
.SYNOPSIS
    Installs the CrowdStrike Falcon sensor on Windows.
.DESCRIPTION
    Authenticates with the CrowdStrike API, downloads the N-1 Falcon sensor
    installer for Windows, validates its integrity, installs it silently, and
    runs a post-install health check.
.NOTES
    Requires PowerShell 3.0 or higher.
    Must be run as Administrator.
    Credentials are read from environment variables:
        CS_CLIENT_ID     - CrowdStrike API Client ID
        CS_CLIENT_SECRET - CrowdStrike API Client Secret
        CS_BASE_URL      - CrowdStrike API Base URL (e.g. https://api.us-2.crowdstrike.com)
#>

# PowerShell version check
if ($PSVersionTable.PSVersion.Major -lt 3) {
    Write-Host "PowerShell 3.0 or higher is required."
    exit 1
}

# Admin check
$CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object Security.Principal.WindowsPrincipal($CurrentUser)
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "This script must be run as Administrator."
    exit 1
}

# Logging
$LogTimestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$LogFile = "C:\Windows\Temp\falcon-install-$LogTimestamp.log"
Start-Transcript -Path $LogFile -Append | Out-Null
Write-Host "Logging install output to $LogFile"

# Credentials and config — set CS_CLIENT_ID, CS_CLIENT_SECRET, CS_BASE_URL as environment
# variables before running. Generate API credentials at:
# https://falcon.crowdstrike.com/api-clients-and-keys
# CS_BASE_URL example: https://api.us-2.crowdstrike.com (varies by cloud region)
$ClientId     = $env:CS_CLIENT_ID
$ClientSecret = $env:CS_CLIENT_SECRET
$BaseUrl      = $env:CS_BASE_URL
$DownloadDir  = $env:TEMP

function Fail {
    param([string]$Message)
    Write-Host $Message
    Stop-Transcript | Out-Null
    exit 1
}

function Invoke-PostInstallHealthCheck {
    $MaxWaitSeconds = 30
    $Waited = 0
    $ServiceState = $null

    Write-Host "Running post-install sensor health checks..."

    while ($Waited -lt $MaxWaitSeconds) {
        $svc = Get-Service -Name "CSFalconService" -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq "Running") {
            $ServiceState = "Running"
            break
        }
        Start-Sleep -Seconds 2
        $Waited += 2
    }

    if ($ServiceState -eq "Running") {
        Write-Host "HEALTHCHECK: PASS - CSFalconService is running"
        return $true
    }

    $StateLabel = if ($ServiceState) { $ServiceState } else { "unknown" }
    Write-Host "HEALTHCHECK: FAIL - service_state=$StateLabel"
    return $false
}

# Validate credentials
if (-not $ClientId -or -not $ClientSecret) {
    Fail "Please set ClientId and ClientSecret before running this script."
}

if (-not $BaseUrl) {
    Fail "Please set BaseUrl before running this script."
}

# Validate OS
if ($env:OS -ne "Windows_NT") {
    Fail "This script is intended for Windows only."
}

# Detect architecture
$Arch = $env:PROCESSOR_ARCHITECTURE
Write-Host "Detected architecture: $Arch"

# Authenticate
Write-Host "Authenticating with CrowdStrike API..."
try {
    $AuthResponse = Invoke-RestMethod `
        -Uri "$BaseUrl/oauth2/token" `
        -Method Post `
        -ContentType "application/x-www-form-urlencoded" `
        -Body "client_id=$ClientId&client_secret=$ClientSecret"
    $AccessToken = $AuthResponse.access_token
} catch {
    Fail "API authentication failed: $_"
}

if (-not $AccessToken) {
    Fail "API authentication failed. Please check API keys."
}

$Headers = @{ Authorization = "Bearer $AccessToken" }

# Check if sensor is already installed
$ExistingService = Get-Service -Name "CSFalconService" -ErrorAction SilentlyContinue

if ($ExistingService) {
    Write-Host "Falcon sensor service found"

    if ($ExistingService.Status -eq "Running") {
        Write-Host "Falcon sensor is installed and running"
        Stop-Transcript | Out-Null
        exit 0
    }

    if ($ExistingService.Status -eq "Stopped") {
        Write-Host "Falcon sensor service is stopped. Attempting to restart..."
        Start-Service -Name "CSFalconService" -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3

        $svc = Get-Service -Name "CSFalconService" -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq "Running") {
            Write-Host "Falcon sensor service is now running"
            Stop-Transcript | Out-Null
            exit 0
        } else {
            Write-Host "Falcon sensor service is still not running. Installation will begin shortly..."
        }
    }
} else {
    Write-Host "Falcon sensor service not found. Installation will begin shortly..."
}

# Get CCID from API
Write-Host "Retrieving CCID from CrowdStrike API..."
try {
    $CcidResponse = Invoke-RestMethod `
        -Uri "$BaseUrl/sensors/queries/installers/ccid/v1" `
        -Method Get `
        -Headers $Headers
    $Ccid = $CcidResponse.resources[0]
} catch {
    Fail "Failed to retrieve CCID from CrowdStrike API: $_"
}

if (-not $Ccid) {
    Fail "Failed to retrieve CCID from CrowdStrike API."
}

# Get installer SHA256 (N-1 version)
Write-Host "Retrieving Windows sensor installer checksum..."
try {
    $ChecksumResponse = Invoke-RestMethod `
        -Uri "$BaseUrl/sensors/queries/installers/v2?offset=1&limit=1&sort=version%7Cdesc&filter=platform%3A%22windows%22" `
        -Method Get `
        -Headers $Headers
    $InstallerSha256 = $ChecksumResponse.resources[0]
} catch {
    Fail "Failed to retrieve Windows installer checksum from CrowdStrike API: $_"
}

if (-not $InstallerSha256) {
    Fail "Failed to retrieve Windows installer checksum from CrowdStrike API."
}

# Get installer filename and version from SHA256
Write-Host "Retrieving installer metadata..."
try {
    $MetaResponse = Invoke-RestMethod `
        -Uri "$BaseUrl/sensors/entities/installers/v2?ids=$InstallerSha256" `
        -Method Get `
        -Headers $Headers
    $InstallerName    = $MetaResponse.resources[0].name
    $InstallerVersion = $MetaResponse.resources[0].version
} catch {
    Fail "Failed to retrieve Windows installer metadata from CrowdStrike API: $_"
}

if (-not $InstallerName) {
    Fail "Failed to retrieve Windows installer filename from CrowdStrike API."
}

Write-Host "Target sensor version: $InstallerVersion"

# Download installer
$InstallerPath = Join-Path $DownloadDir $InstallerName
Write-Host "Attempting to download Windows Falcon sensor to $InstallerPath..."

try {
    Invoke-WebRequest `
        -Uri "$BaseUrl/sensors/entities/download-installer/v1?id=$InstallerSha256" `
        -Method Get `
        -Headers $Headers `
        -OutFile $InstallerPath
} catch {
    Fail "Windows Falcon sensor download failed: $_"
}

# Validate download exists and is non-empty
if (-not (Test-Path $InstallerPath) -or (Get-Item $InstallerPath).Length -eq 0) {
    Fail "Windows Falcon sensor download is missing or empty."
}

# Validate SHA256 integrity
Write-Host "Validating installer integrity..."
$DownloadedHash = (Get-FileHash -Path $InstallerPath -Algorithm SHA256).Hash.ToLower()
if ($DownloadedHash -ne $InstallerSha256.ToLower()) {
    Fail "SHA256 mismatch. Expected: $InstallerSha256 | Got: $DownloadedHash"
}
Write-Host "SHA256 validation passed"

# Install sensor silently with CID
Write-Host "Starting Windows Falcon sensor install..."
try {
    $Process = Start-Process `
        -FilePath $InstallerPath `
        -ArgumentList "/install /quiet /norestart CID=$Ccid" `
        -Wait `
        -PassThru
    if ($Process.ExitCode -ne 0) {
        Fail "Sensor installation failed with exit code: $($Process.ExitCode)"
    }
} catch {
    Fail "Sensor installation failed: $_"
}

Write-Host "Sensor installation complete. Waiting for service to initialize..."
Start-Sleep -Seconds 3

# Ensure service is started
$svc = Get-Service -Name "CSFalconService" -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -ne "Running") {
    Start-Service -Name "CSFalconService" -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
}

# Post-install health check
if (-not (Invoke-PostInstallHealthCheck)) {
    Fail "Post-install sensor health check failed."
}

# Show final service status
Get-Service -Name "CSFalconService"

Stop-Transcript | Out-Null
