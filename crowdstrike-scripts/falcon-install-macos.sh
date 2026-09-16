#!/bin/bash

# logging folder and location for falcon sensor install script
LOG_TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="/var/log/falcon-install-${LOG_TIMESTAMP}.log"

if ! touch "$LOG_FILE" 2>/dev/null; then
        echo "Unable to create log file at $LOG_FILE. Re-run with sufficient permissions."
        exit 1
fi
exec > >(tee -a "$LOG_FILE") 2>&1
echo "Logging install output to $LOG_FILE"

# falcon sensor download dir and API creds
# Set CS_CLIENT_ID, CS_CLIENT_SECRET, and CS_BASE_URL as environment variables before running.
# Generate API credentials at: https://falcon.crowdstrike.com/api-clients-and-keys
# CS_BASE_URL example: https://api.us-2.crowdstrike.com (varies by cloud region)
DOWNLOAD_DIRECTORY="/tmp"
CLIENT_ID="${CS_CLIENT_ID:-}"
CLIENT_SECRET="${CS_CLIENT_SECRET:-}"
BASE_URL="${CS_BASE_URL:-}"

FALCONCTL="/Applications/Falcon.app/Contents/Resources/falconctl"

fail() {
        echo "$1"
        exit 1
}

post_install_health_check() {
        local max_wait_seconds=30
        local waited=0
        local falcon_running=false
        local sensor_cid=""

        echo "Running post-install sensor health checks..."

        while [ "$waited" -lt "$max_wait_seconds" ]; do
                if pgrep -x "falcond" > /dev/null 2>&1; then
                        falcon_running=true
                        break
                fi
                sleep 2
                waited=$((waited + 2))
        done

        if [ -x "$FALCONCTL" ]; then
                sensor_cid=$(sudo "$FALCONCTL" stats 2>/dev/null | grep -i "Customer ID" | awk -F': ' '{print $2}' | tr -d '[:space:]')
        fi

        if [ "$falcon_running" = true ] && [ -n "$sensor_cid" ]; then
                echo "HEALTHCHECK: PASS - falcond is running and CID is configured"
                echo "HEALTHCHECK: CID=$sensor_cid"
                return 0
        fi

        echo "HEALTHCHECK: FAIL - falcon_running=${falcon_running}, cid_present=$([ -n "$sensor_cid" ] && echo yes || echo no)"
        return 1
}

check_system_extension() {
        echo "Checking System Extension status..."

        if ! command -v systemextensionsctl > /dev/null 2>&1; then
                echo "SYSEXT: systemextensionsctl not available (macOS 10.15+ required)"
                return
        fi

        local sysext_status
        sysext_status=$(systemextensionsctl list 2>/dev/null | grep -i "crowdstrike")

        if [ -n "$sysext_status" ]; then
                echo "SYSEXT: CrowdStrike System Extension found:"
                echo "$sysext_status"
        else
                echo "SYSEXT: WARNING - CrowdStrike System Extension not yet approved."
                echo "SYSEXT: Action required: Go to System Settings > Privacy & Security and approve the CrowdStrike extension."
                echo "SYSEXT: For automated deployments, configure a PPPC MDM profile before deploying."
        fi
}

check_full_disk_access() {
        echo "Checking Full Disk Access (FDA) status..."

        # Attempt to read a FDA-protected path as a proxy check
        if ls /Library/Application\ Support/com.apple.TCC > /dev/null 2>&1; then
                echo "FDA: Full Disk Access appears to be granted to this process."
        else
                echo "FDA: WARNING - Full Disk Access may not be granted to the Falcon sensor."
                echo "FDA: Action required: Go to System Settings > Privacy & Security > Full Disk Access"
                echo "FDA: and enable access for Falcon.app and falcond."
                echo "FDA: For automated deployments, configure a PPPC MDM profile before deploying."
        fi
}

# check client id and secret are set
if [ -z "$CLIENT_ID" ] || [ -z "$CLIENT_SECRET" ]; then
        fail "Please set CLIENT_ID and CLIENT_SECRET before running this script."
fi

if [ -z "$BASE_URL" ]; then
        fail "Please set BASE_URL before running this script."
fi

# must run as root
if [ "$(id -u)" -ne 0 ]; then
        fail "This script must be run as root (sudo)."
fi

# validate running on macOS
OS_TYPE=$(uname -s)
if [ "$OS_TYPE" != "Darwin" ]; then
        fail "This script is intended for macOS only. Detected OS: $OS_TYPE"
fi

# detect architecture (informational — installer is universal)
ARCH=$(uname -m)
echo "Detected architecture: $ARCH (universal installer covers arm64 and x86_64)"

# validate curl and jq
if ! command -v curl > /dev/null 2>&1; then
        fail "curl is required but not installed."
fi

if ! command -v jq > /dev/null 2>&1; then
        echo "jq not found. Attempting to install jq..."

        # resolve the original non-root user for brew (brew refuses to run as root)
        ORIGINAL_USER=$(logname 2>/dev/null || echo "")

        # try brew as original user first
        if [ -n "$ORIGINAL_USER" ] && sudo -u "$ORIGINAL_USER" command -v brew > /dev/null 2>&1; then
                echo "Installing jq via Homebrew as $ORIGINAL_USER..."
                sudo -u "$ORIGINAL_USER" brew install jq
        else
                # fall back to downloading jq binary directly (works as root)
                echo "Homebrew unavailable as root. Downloading jq binary directly..."
                JQ_INSTALL_PATH="/usr/local/bin/jq"

                if [ "$ARCH" = "arm64" ]; then
                        JQ_URL="https://github.com/jqlang/jq/releases/latest/download/jq-macos-arm64"
                else
                        JQ_URL="https://github.com/jqlang/jq/releases/latest/download/jq-macos-amd64"
                fi

                if ! curl --silent --show-error --fail --location "$JQ_URL" --output "$JQ_INSTALL_PATH"; then
                        fail "jq binary download failed. Please install jq manually: brew install jq"
                fi
                chmod +x "$JQ_INSTALL_PATH"
        fi

        if ! command -v jq > /dev/null 2>&1; then
                fail "jq installation failed. Please install jq manually: brew install jq"
        fi
        echo "jq installed successfully"
fi

CURL_FLAGS=(--silent --show-error --fail)

# authenticate with CrowdStrike API
ACCESS_TOKEN=$(curl "${CURL_FLAGS[@]}" --request POST "$BASE_URL/oauth2/token" \
        --header "Content-Type: application/x-www-form-urlencoded" \
        --data-urlencode "client_id=$CLIENT_ID" \
        --data-urlencode "client_secret=$CLIENT_SECRET" | jq -r '.access_token')

if [ -z "$ACCESS_TOKEN" ] || [ "$ACCESS_TOKEN" = "null" ]; then
        fail "API authentication failed. Please check API keys."
fi

# check if falcon sensor is already installed
if [ -d "/Applications/Falcon.app" ]; then
        echo "Falcon.app found in /Applications"

        if pgrep -x "falcond" > /dev/null 2>&1; then
                echo "Falcon sensor is installed and running"
                exit 0
        else
                echo "Falcon sensor is installed but not running. Attempting to start..."
                sudo launchctl load /Library/LaunchDaemons/com.crowdstrike.falcon.App.plist 2>/dev/null || true
                sleep 3

                if pgrep -x "falcond" > /dev/null 2>&1; then
                        echo "Falcon sensor is now running"
                        exit 0
                else
                        echo "Falcon sensor is still not running. Installation will begin shortly..."
                fi
        fi
else
        echo "Falcon.app not found. Installation will begin shortly..."
fi

# get CCID from API
echo "Retrieving CCID from CrowdStrike API..."
CCID=$(curl "${CURL_FLAGS[@]}" --request GET "$BASE_URL/sensors/queries/installers/ccid/v1" \
        --header "accept: application/json" \
        --header "authorization: Bearer $ACCESS_TOKEN" | jq -r '.resources[0]')

if [ -z "$CCID" ] || [ "$CCID" = "null" ]; then
        fail "Failed to retrieve CCID from CrowdStrike API."
fi

# get macOS sensor SHA256 (N-1 version)
echo "Retrieving macOS sensor installer checksum..."
MACOS_CHECKSUM=$(curl "${CURL_FLAGS[@]}" --request GET "$BASE_URL/sensors/queries/installers/v2?offset=1&limit=1&sort=version%7Cdesc&filter=platform%3A%22mac%22" \
        --header "accept: application/json" \
        --header "authorization: Bearer $ACCESS_TOKEN" | jq -r '.resources[0]')

if [ -z "$MACOS_CHECKSUM" ] || [ "$MACOS_CHECKSUM" = "null" ]; then
        fail "Failed to retrieve macOS installer checksum from CrowdStrike API."
fi

# get installer filename and version from SHA256
MACOS_META=$(curl "${CURL_FLAGS[@]}" --request GET "$BASE_URL/sensors/entities/installers/v2?ids=$MACOS_CHECKSUM" \
        --header "accept: application/json" \
        --header "authorization: Bearer $ACCESS_TOKEN")

MACOS_FILENAME=$(echo "$MACOS_META" | jq -r '.resources[0].name')
MACOS_VERSION=$(echo "$MACOS_META" | jq -r '.resources[0].version')

if [ -z "$MACOS_FILENAME" ] || [ "$MACOS_FILENAME" = "null" ]; then
        fail "Failed to retrieve macOS installer filename from CrowdStrike API."
fi

echo "Target sensor version: $MACOS_VERSION"

# download macOS falcon sensor to /tmp
echo "Attempting to download macOS Falcon sensor..."
if ! curl "${CURL_FLAGS[@]}" --location --request GET "$BASE_URL/sensors/entities/download-installer/v1?id=$MACOS_CHECKSUM" \
        --header "accept: application/json" \
        --header "authorization: Bearer $ACCESS_TOKEN" \
        --output "$DOWNLOAD_DIRECTORY/$MACOS_FILENAME"; then
        fail "macOS Falcon sensor download failed."
fi

# validate download
if [ ! -s "$DOWNLOAD_DIRECTORY/$MACOS_FILENAME" ]; then
        fail "macOS Falcon sensor download is missing or empty."
fi

# validate SHA256 integrity
echo "Validating installer integrity..."
DOWNLOADED_HASH=$(shasum -a 256 "$DOWNLOAD_DIRECTORY/$MACOS_FILENAME" | awk '{print $1}')
if [ "$DOWNLOADED_HASH" != "$MACOS_CHECKSUM" ]; then
        fail "SHA256 mismatch. Expected: $MACOS_CHECKSUM | Got: $DOWNLOADED_HASH"
fi
echo "SHA256 validation passed"

# install macOS falcon sensor
echo "macOS Falcon sensor downloaded successfully"
echo "Starting macOS Falcon sensor install..."
if ! installer -pkg "$DOWNLOAD_DIRECTORY/$MACOS_FILENAME" -target /; then
        fail "macOS Falcon sensor install failed."
fi
sleep 3

# register sensor with CID
if [ -x "$FALCONCTL" ]; then
        echo "Registering sensor with CID..."
        if ! sudo "$FALCONCTL" license "$CCID"; then
                fail "Sensor CID registration failed."
        fi
else
        fail "falconctl not found at $FALCONCTL. Installation may have failed."
fi
sleep 3

# check System Extension approval status
check_system_extension

# check Full Disk Access status
check_full_disk_access

# post-install health check
if ! post_install_health_check; then
        fail "Post-install sensor health check failed."
fi

# show final sensor stats
echo "Falcon sensor status:"
sudo "$FALCONCTL" stats 2>/dev/null || true
