#!/bin/bash

# attempt to killall applications safely

applications=("Google Chrome" "Spotify" "Terminal" "iTerm2" "Notes" "TextEdit" "Code")

for app in "${applications[@]}"; do
	killall "$app" 2>/dev/null || echo "$app was not running."
done

sleep 2
sudo shutdown -r now