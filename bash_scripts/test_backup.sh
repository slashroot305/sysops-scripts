#!/bin/bash

#================================================#
# Scope:
#   
# Description: 
#   Backs up folder from one location to another.
#
# Notes
#   Version: 1.0
#   Author: Jojo A
#
# Creation date & time: 11/25/2025 19:00 CST
# Date last modified: 12/01/2025 18:29 CST
# Last modified by: Jojo A
#================================================#

# define source and destination locations
source_path="/path/to/source"
destination_path="/path/to/destination"
main_copy_path="/path/to/main copy"
backup_copy_path="/path/to/backup copy"

# check source and destination paths exists
if [ -d "$source_path" ] && [ -d "$destination_path" ]; then
    echo "source path exists: "$source_path""
    echo "desitnation path exists: "$destination_path""
else
    echo "both paths does not exist. check source and destination paths"
fi

# duplicate source folder in source location and send duplicate to backup drive
if [ -d "$source_path" ]; then
    rsync -avh --info=progress2 "$source_path" "$main_copy_path"
    sleep 3
    if [ -d "$main_copy_path" ]; then
        echo "duplicate successful"
        echo "moving duplicate to backup now..."
        sleep 2
        mv "$main_copy_path" "$destination_path"
        sleep 1
        if [ -d "$backup_copy_path" ]; then
            echo "move successful"
        fi
    else
        echo "copy of $main_copy_path not successful so move failed"
        echo "check rsync command and paths"
    fi

else
    echo "check source path $source_path"
fi