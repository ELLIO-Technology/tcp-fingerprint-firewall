#\!/bin/bash
#
# check_btf.sh
#
# This software is dual-licensed under:
# - GNU Affero General Public License v3.0 (AGPLv3) - for those willing to comply with AGPLv3 terms
# - Proprietary license - for those who cannot or do not want to adhere to AGPLv3 terms
#
# If you do not want to be bound by the AGPLv3 terms (such as releasing source code
# for modifications or network usage), you must acquire a proprietary license.
#
# See the LICENSE file for details.


# Check for available BTF support on the system
if [ \! -f /sys/kernel/btf/vmlinux ]; then
    echo "WARNING: BTF information not available in /sys/kernel/btf/vmlinux"
    echo "This could cause problems loading the eBPF program."
    
    # Check kernel version - BTF is generally available in kernel 5.5+
    KERNEL_VERSION=$(uname -r)
    KERNEL_MAJOR=$(echo $KERNEL_VERSION | cut -d. -f1)
    KERNEL_MINOR=$(echo $KERNEL_VERSION | cut -d. -f2)
    
    echo "Kernel version: $KERNEL_VERSION"
    
    if [ "$KERNEL_MAJOR" -lt 5 ] || [ "$KERNEL_MAJOR" -eq 5 -a "$KERNEL_MINOR" -lt 5 ]; then
        echo "Your kernel ($KERNEL_VERSION) may be too old for BTF support."
        echo "Consider using kernel 5.5+ for best compatibility."
    else
        echo "Your kernel version should support BTF, but it might not be enabled."
    fi
    
    # Warn about compatibility
    echo ""
    echo "Recommendation: Update your kernel to 5.5+ for best compatibility."
else
    echo "BTF information available - eBPF program should load correctly."
fi
