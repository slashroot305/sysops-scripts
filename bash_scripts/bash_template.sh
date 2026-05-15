#!/bin/bash
# ========================================
# Script Name: my_script.sh
# Description: Example Bash script structure
# Author: Jojo Adu
# ========================================

# --- Global Variables ---
NAME="Jojo"
LOG_FILE="./script.log"

# --- Functions ---
log_message() {
    # $1 = message
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

greet_user() {
    echo "Hello, $NAME!"
    log_message "Greeted $NAME"
}

sum_numbers() {
    # $1 = first number, $2 = second number
    local sum=$(( $1 + $2 ))
    echo "$sum"
}

# --- Main Script Execution ---
echo "Starting script..."
greet_user

result=$(sum_numbers 5 7)
echo "The sum is $result"
log_message "Calculated sum: $result"

echo "Script finished!"