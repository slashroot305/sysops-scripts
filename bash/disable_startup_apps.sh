# mac bash script to disable startup apps
APPS=("Splice" "Spotify")
for APP in "${APPS[@]}"; do
osascript -e "tell application \"System Events\" to delete login item \"$APP\"" done
echo "selected apps disabled from startup."