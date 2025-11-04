<#
    Scope: software removal validation

    Description: checks software installation
    path(s) to vaildate if present or not
    and send information to logscale.

    Notes
    Version: 1.0
    Creator & maintainer: Jojo A

    Creation date & time: 03/21/2024 23:00
    Date last modified: 11/03/2025 21:21
#>

# a generic logging function
function logger ($Message, $Level="Info") {
    $Date = Get-Date
    $Level = $Level.ToUpper()
    $LogLine = "{0} -{1} -{2} - {3}" -f $Date, $Level, $scriptName, $Message

    if ($DebugMode) {
        Write-Output $LogLine.ToUpper()
    }
    $LogLine | Add-Content $LogFile
}

function SendTo-Logscale() {
    # sends a single string object to humio

    param(
        $Log,
        [string]$hostname,
        [string]$Source = "script_name_here",
        [string]$Token
    )

# insert url to orginization's logscale query page. This is an example for ABC
$URL = ""
$Headers = @{ Authorization = 'Bearer', $Token -join ' '; ContentType = 'text/plain'}

    try {
        # ConvertFrom-Json does not respect ErrorActions, :(
        # Run a check here to see if ts a string and if its already json.
        $Jsonlog = $Log | ConvertFrom-Json
    }
    catch {
    }

    # check if its a string line or an object
    if ($Log.GetType() -ne ''.GetType()) {
        # convert the object to a json string
        $Log = $Log | ConvertTo-Json -Depth 1
    }
    elseif (!$Jsonlog) {
        # if its not directly JSON, make it JSON
        $Log = @{"Message" = $Log; "Type" = "Message"; "Source" = $Source}
        if ($hostname) {
            # if a hostname is passed in, use it
            $Log["hostname"] = $hostname
        }
        # convert the line to JSON
        $Log = $Log | ConvertTo-Json -Depth 1
    }

    # put it on a single line
    $Log = $Log -replace [System.Environment]::NewLine, ''
    # send it
    Invoke-WebRequest -Uri $URL -Method 'Post' -Headers $Headers -Body $Log -UseBasicParsing | Out-Null
}

$Data = @{}
$Hostname = hostname
$Data["ComputerName"] = $Hostname
$Data["DataType"] = ""

# now to the actual checking. using SEP as an example

# silence any errors that may happen
$ErrorActionPreference = 'SilentlyContinue'

# variables to store the results of the commands
$SEP_service = get-service -name 'sepmasterservice'
$SEP_installation_folder = Test-Path 'path-to-test'
$SEP_registry = Get-ItemProperty -Path 'path-to-registry'
<# registry location for SEP:
HKLM:\SOFTWARE\Symantec\WOW6432Node\Symantec\Symantec Endpoint Protection\CurrentVersion\Public-opstate
#>

#  check the various locations for SEP
if ($SEP_service) {
    $hasSEPService = "Present"
} else {
    $hasSEPService = "Not Present"
}
if ($SEP_installation_folder -eq $true) {
    $hasSepInstallationFolder = "Present"
} else {
    $hasSepInstallationFolder = "Not Present"
}
if ($SEP_registry -eq $true) {
    $hasSepRegistryKey = "Present"
} else {
    $hasSepRegistryKey = "Not Present"
}

# print in a nice csv format (optional), using SEP as an exampple
$hostname = hostname
$SEPValidation = [PSCustomObject]@{
    'SEP Service' = $hasSEPService
    'SEP Folder' = $hasSepInstallationFolder
    'SEP Registry Key' = $hasSepRegistryKey
    'ComputerName' = $hostname
    'DataType' = "SEP Check"
}
Write-Output $SEPValidation

# send to logscale. token lenght: 36 token format: 8-4-4-4-12 
SendTo-Logscale $SEPValidation -token "enter-logscale-token"

# end