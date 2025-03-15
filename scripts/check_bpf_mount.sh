#!/bin/bash
#
# check_bpf_mount.sh
#
# This software is dual-licensed under:
# - GNU Affero General Public License v3.0 (AGPLv3) - for those willing to comply with AGPLv3 terms
# - Proprietary license - for those who cannot or do not want to adhere to AGPLv3 terms
#
# If you do not want to be bound by the AGPLv3 terms (such as releasing source code
# for modifications or network usage), you must acquire a proprietary license.
#
# See the LICENSE file for details.


# Check if BPF filesystem is mounted
if ! mount | grep -q "bpffs on /sys/fs/bpf"; then
    echo "BPF filesystem not mounted. Attempting to mount it..."
    if [ ! -d /sys/fs/bpf ]; then
        echo "Creating /sys/fs/bpf directory..."
        sudo mkdir -p /sys/fs/bpf
    fi
    
    echo "Mounting BPF filesystem..."
    sudo mount -t bpf bpffs /sys/fs/bpf
    
    if mount | grep -q "bpffs on /sys/fs/bpf"; then
        echo "Successfully mounted BPF filesystem."
    else
        echo "Failed to mount BPF filesystem."
        echo "You may need to run: sudo mount -t bpf bpffs /sys/fs/bpf"
        exit 1
    fi
else
    echo "BPF filesystem is already mounted."
fi

# Check permissions on /sys/fs/bpf
if [ ! -w /sys/fs/bpf ]; then
    echo "Warning: /sys/fs/bpf is not writable by the current user."
    echo "If you encounter permission issues, try:"
    echo "  sudo chmod 755 /sys/fs/bpf"
fi

# Check if unprivileged BPF is disabled
if [ -f /proc/sys/kernel/unprivileged_bpf_disabled ]; then
    UNPRIVILEGED_BPF=$(cat /proc/sys/kernel/unprivileged_bpf_disabled)
    if [ "$UNPRIVILEGED_BPF" -eq "1" ]; then
        echo "Unprivileged BPF is disabled. This is good for security."
        echo "Make sure to run the program with sudo."
    else
        echo "Warning: Unprivileged BPF is enabled. This may be a security risk."
    fi
fi

echo "BPF environment check completed."