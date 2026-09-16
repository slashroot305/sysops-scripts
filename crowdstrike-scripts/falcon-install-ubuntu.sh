#!/bin/bash

# logging foler and location for falcon sensor install script
LOG_TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="/var/log/falcon-install-${LOG_TIMESTAMP}.log"

# Capture all script output to a timestamped log while still printing to console.
if ! touch "$LOG_FILE" 2>/dev/null; then
        echo "Unable to create log file at $LOG_FILE. Re-run with sufficient permissions."
        exit 1
fi
exec > >(tee -a "$LOG_FILE") 2>&1
echo "Logging install output to $LOG_FILE"

# falcon sensor download dir, service check, architecture detection, and API creds
# Set CS_CLIENT_ID and CS_CLIENT_SECRET as environment variables before running.
# Generate API credentials at: https://falcon.crowdstrike.com/api-clients-and-keys
DOWNLOAD_DIRECTORY="/tmp"
SERVICE_STATUS=$(systemctl is-active falcon-sensor 2>/dev/null || true)
ARCH=$(uname -m)
CLIENT_ID="${CS_CLIENT_ID:-}"
CLIENT_SECRET="${CS_CLIENT_SECRET:-}"

fail() {
        echo "$1"
        exit 1
}

post_install_health_check() {
        local max_wait_seconds=30
        local waited=0
        local service_state=""
        local sensor_cid=""

        echo "Running post-install sensor health checks..."

        while [ "$waited" -lt "$max_wait_seconds" ]; do
                service_state=$(systemctl is-active falcon-sensor 2>/dev/null || true)
                if [ "$service_state" = "active" ]; then
                        break
                fi
                sleep 2
                waited=$((waited + 2))
        done

        sensor_cid=$(/opt/CrowdStrike/falconctl -g --cid 2>/dev/null | sed -n 's/^cid="\([^"]\+\)".*/\1/p')

        if [ "$service_state" = "active" ] && [ -n "$sensor_cid" ]; then
                echo "HEALTHCHECK: PASS - falcon-sensor is active and CID is configured"
                echo "HEALTHCHECK: CID=$sensor_cid"
                return 0
        fi

        echo "HEALTHCHECK: FAIL - service_state=${service_state:-unknown}, cid_present=$([ -n "$sensor_cid" ] && echo yes || echo no)"
        return 1
}

wait_for_dpkg_lock() {
        local lock_file="/var/lib/dpkg/lock-frontend"
        local max_wait_seconds=300
        local waited=0

        while command -v fuser >/dev/null 2>&1 && fuser "$lock_file" >/dev/null 2>&1; do
                if [ "$waited" -ge "$max_wait_seconds" ]; then
                        fail "Timed out waiting for dpkg lock after ${max_wait_seconds}s"
                fi
                echo "dpkg lock is busy. Waiting 5s..."
                sleep 5
                waited=$((waited + 5))
        done
}

dpkg_install_with_retry() {
        local sensor_pkg="$1"
        local max_attempts=20
        local attempt=1

        while [ "$attempt" -le "$max_attempts" ]; do
                wait_for_dpkg_lock
                if dpkg -i "$sensor_pkg"; then
                        return 0
                fi

                echo "dpkg install attempt ${attempt}/${max_attempts} failed. Retrying in 3s..."
                sleep 3
                attempt=$((attempt + 1))
        done

        return 1
}

install_sensor_package() {
        local sensor_pkg="$1"
        dpkg_install_with_retry "$sensor_pkg"
}

# check client id and secret is set
if [ -z "$CLIENT_ID" ] || [ -z "$CLIENT_SECRET" ]; then
        fail "Please set Client ID and Secret"
fi

# check for jq and install if not present
if ! command -v jq &>/dev/null; then
        echo "jq not found. Attempting to install jq..."
        if [ -r /etc/os-release ]; then
                . /etc/os-release
        fi

        if [[ "${ID:-}" == "debian" || "${ID:-}" == "ubuntu" || " ${ID_LIKE:-} " == *" debian "* ]]; then
                if command -v apt-get &>/dev/null; then
                        apt-get update && apt-get -y install jq
                else
                        echo "Debian-based distro detected but apt-get is not available. Install jq manually."
                        exit 1
                fi
        else
                echo "Non-Debian distro detected. Install jq manually before running this script."
                exit 1
        fi
        if ! command -v jq &>/dev/null; then
                echo "jq installation failed. Please install jq manually and re-run the script."
                exit 1
        fi
        echo "jq installed successfully"
fi

# validate curl exists and use portable flags supported on Debian/Ubuntu curl builds
if ! command -v curl &>/dev/null; then
        fail "curl is required but not installed. Install curl and re-run the script."
fi

CURL_FLAGS=(--silent --show-error --fail)

# authenticate with CrowdStrike's API to get access token
ACCESS_TOKEN=$(curl "${CURL_FLAGS[@]}" --request POST "https://api.us-2.crowdstrike.com/oauth2/token" --header "Content-Type: application/x-www-form-urlencoded" --data-urlencode "client_id=$CLIENT_ID" --data-urlencode "client_secret=$CLIENT_SECRET" | jq -r '.access_token')

if [ -z "$ACCESS_TOKEN" ] || [ "$ACCESS_TOKEN" = "null" ]; then
        fail "API authentication failed. Please check API keys"
fi

# verify Ubuntu os name and version
UBUNTU_OS_RELEASE=$(grep -E '^NAME=' /etc/os-release | cut -d= -f2 | tr -d '"' | cut -d' ' -f1)
UBUNTU_NAME="Ubuntu"

if [[ $UBUNTU_OS_RELEASE == $UBUNTU_NAME ]]; then
        echo "System is Ubuntu"
fi

# get Ubuntu version number i.e., 16,18,20,22,24
UBUNTU_VERSION=$(grep -E '^VERSION_ID=' /etc/os-release | cut -d= -f2 | tr -d '"' | cut -d. -f1)

# downlaod and install falcon sensor for Ubuntu
if [ "$UBUNTU_VERSION" -eq 16 ] || [ "$UBUNTU_VERSION" -eq 18 ] || [ "$UBUNTU_VERSION" -eq 20 ] || [ "$UBUNTU_VERSION" -eq 22 ] || [ "$UBUNTU_VERSION" -eq 24 ]; then
        echo "System version is Ubuntu $UBUNTU_VERSION"

        if [ "$ARCH" = "aarch64" ] && [ "$UBUNTU_VERSION" -eq 16 ]; then
                fail "Ubuntu 16 is not supported on aarch64. Supported versions are 18, 20, 22, and 24."
        fi

        # check dpkg database for falcon sensor install package
        if dpkg -l | grep -q falcon-sensor; then
                echo "Falcon install file found in dpkg database"

                # check if falcon sensor service is running
                if systemctl is-active --quiet falcon-sensor; then
                        echo "Falcon sensor is installed and running"
		        exit 0
                fi

                # check if falcon sensor is in a failed state
                if systemctl is-failed --quiet falcon-sensor; then
                        echo "Falcon sensor service is not running"
                        echo "The service is either failed or stopped"
                        echo "Attempting to restart service..."
                        systemctl restart falcon-sensor
                        sleep 3

                        # recheck if falcon sensor service is running
                        if systemctl is-active --quiet falcon-sensor; then
                                echo "Falcon sensor service is now running"
                        else
                                echo "Falcon sensor service is still not running"
                                echo "Installation will begin shortly..."
                        fi
                fi
        else
                # check if falcon sensor service is inactive
                if [ "$SERVICE_STATUS" = "inactive" ]; then
                        echo "The falcon-sensor service is inactive, terminated or not installed"
                        echo "Installation will begin shortly..."
                fi
        fi

        # get falcon sensor SHA256 value for Ubuntu (architecture-aware)
        if [ "$ARCH" = "aarch64" ]; then
                echo "Detected architecture: aarch64"
                UBUNTU_CHECKSUM=$(curl "${CURL_FLAGS[@]}" --request GET "https://api.us-2.crowdstrike.com/sensors/queries/installers/v2?offset=1&limit=1&sort=version%7Cdesc&filter=os%3A%22Ubuntu%22%2Bos_version%3A%2218%2F20%2F22%2F24+-+arm64%22" --header "accept: application/json" --header "authorization: Bearer $ACCESS_TOKEN" | jq -r '.resources[0]')
        else
                echo "Detected architecture: x86_64"
                UBUNTU_CHECKSUM=$(curl "${CURL_FLAGS[@]}" --request GET "https://api.us-2.crowdstrike.com/sensors/queries/installers/v2?offset=1&limit=1&sort=version%7Cdesc&filter=os%3A%22Ubuntu%22%2Bos_version%3A%2216%2F18%2F20%2F22%2F24%22" --header "accept: application/json" --header "authorization: Bearer $ACCESS_TOKEN" | jq -r '.resources[0]')
        fi
        if [ -z "$UBUNTU_CHECKSUM" ] || [ "$UBUNTU_CHECKSUM" = "null" ]; then
                fail "Failed to retrieve Ubuntu installer checksum from CrowdStrike API"
        fi

        # get Ubuntu falcon sensor name from SHA256 value
        UBUNTU_FILENAME=$(curl "${CURL_FLAGS[@]}" --request GET "https://api.us-2.crowdstrike.com/sensors/entities/installers/v2?ids=$UBUNTU_CHECKSUM" --header "accept: application/json" --header "authorization: Bearer $ACCESS_TOKEN" | jq -r '.resources[0].name')
        if [ -z "$UBUNTU_FILENAME" ] || [ "$UBUNTU_FILENAME" = "null" ]; then
                fail "Failed to retrieve Ubuntu installer filename from CrowdStrike API"
        fi

        # download Ubuntu falcon sensor to /tmp dir
        echo "Attempting to download Ubuntu falcon sensor"
        if ! curl "${CURL_FLAGS[@]}" --location --request GET "https://api.us-2.crowdstrike.com/sensors/entities/download-installer/v1?id=$UBUNTU_CHECKSUM" --header "accept: application/json" --header "authorization: Bearer $ACCESS_TOKEN" --output "$DOWNLOAD_DIRECTORY/$UBUNTU_FILENAME"; then
                fail "Ubuntu falcon sensor download failed"
        fi

        # validate Ubuntu falcon sensor download
        if [ ! -s "$DOWNLOAD_DIRECTORY/$UBUNTU_FILENAME" ]; then
                fail "Ubuntu falcon sensor download is missing or empty"
        else
                echo "Ubuntu falcon sensor downloaded successfully"
                echo "Starting Ubuntu falcon install..."

                # install Ubuntu falcon sensor
                if ! install_sensor_package "$DOWNLOAD_DIRECTORY/$UBUNTU_FILENAME"; then
                        fail "Ubuntu falcon sensor install failed"
                fi
                sleep 3
        fi

        # validate CrowdStrike install path exists
        if [ -e /opt/CrowdStrike ]; then

                # retrieve CID from API and register sensor
                CID=$(curl "${CURL_FLAGS[@]}" --request GET "https://api.us-2.crowdstrike.com/sensors/queries/installers/ccid/v1" \
                        --header "accept: application/json" \
                        --header "authorization: Bearer $ACCESS_TOKEN" | jq -r '.resources[0]')
                if [ -z "$CID" ] || [ "$CID" = "null" ]; then
                        fail "Failed to retrieve CID from CrowdStrike API"
                fi
                /opt/CrowdStrike/falconctl -s --cid="$CID"
                if [ $? -ne 0 ]; then
                        fail "Sensor registration failed"
                fi

                # start the falcon sensor service
                systemctl start falcon-sensor
                if [ $? -ne 0 ]; then
                        fail "Failed to start falcon-sensor service"
                fi
                sleep 3

                if ! post_install_health_check; then
                        fail "Post-install sensor health check failed"
                fi
                
                # check the falcon sensor service
                systemctl status falcon-sensor
        fi
else
        fail "Unsupported Ubuntu version: $UBUNTU_VERSION"
fi