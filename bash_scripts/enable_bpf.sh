#!/bin/bash

# Command to check bpf status stored in variable
bpf_status=$(sysctl -n kernel.unprivileged_bpf_disabled)
#bpf_status=$(sysctl kernel.unprivileged_bpf_disabled | rev | cut -c1)
#bpf_status=$(cat /proc/sys/kernel/unprivileged_bpf_disabled)

# Check if BPF is enabled or disabled
# 0 = enabled
# 1 = disabled (permanently)
# 2 = disabled (can be enabled without reboot)
if [ "$bpf_status" -eq 0 ]; then
    echo "BPF is enabled"
elif [ "$bpf_status" -eq 1 ]; then
    echo -e "BPF is hard disabled\nReboot required to enable"
elif [ "$bpf_status" -eq 2 ]; then
    echo -e "BPF is soft disabled\nCan enable without reboot"
fi

# Declare variable again
bpf_status=$(sysctl -n kernel.unprivileged_bpf_disabled)
#bpf_status=$(sysctl kernel.unprivileged_bpf_disabled | rev | cut -c1)
#bpf_status=$(cat /proc/sys/kernel/unprivileged_bpf_disabled)
bpf_enable=$(sysctl kernel.unprivileged_bpf_disabled=0)

# Enable BPF
if [ "$bpf_status" -eq 2 ]; then
    $bpf_enable
    sleep 2
    $bpf_status
    if [ "$bpf_status" -eq 0 ]; then
        echo "BPF was succcessfully enabled"
    else
        echo -e "BPF either disbled or failed to enable\nCheck BPF status"
    fi
fi

exit 0