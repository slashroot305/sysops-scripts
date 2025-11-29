#!/bin/bash

#============================================#
# Scope:
#
# Description: Backs up logic folder from a
#              working external hard drive 
#              location to a back up hard
#              drive location.
# Version: 1.0
#============================================#

# set backup locations
jovybz_main_drive="/Users/jovybz/Desktop/Backup_script_test_env/Folder_A"
backup_drive="/Users/jovybz/Desktop/Backup_script_test_env/Folder_B"
new_copy="/Users/jovybz/Desktop/Backup_script_test_env/Folder_A_new"

# check source and destination paths exists
if [ -d "$jovybz_main_drive" ] && [ -d "$backup_drive" ]; then
    echo "path exists "$jovybz_main_drive""
    echo "path exists "$backup_drive""
else
    echo "paths do not exist. check 'jovybz main' and 'backup' paths"
fi

# backup logic
if [ -d $jovybz_main_drive ]; then
    mv "$jovybz_main_drive" /Users/jovybz/Desktop/Backup_script_test_env/Folder_A_org
    cp -r "$jovybz_main_drive" "$new_copy"
    if [ -d "$new_copy" ]; then
        echo "new folder copy successful "$new_copy""
    else
        echo "No new copies found"
    fi
else
    echo "path does not exist. check 'jovybz main' path"
fi