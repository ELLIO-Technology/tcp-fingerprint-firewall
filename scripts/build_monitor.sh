#!/bin/bash
#
# Simple build script for TCP Fingerprint Monitor
#
# This software is dual-licensed under:
# - GNU Affero General Public License v3.0 (AGPLv3) - for those willing to comply with AGPLv3 terms
# - Proprietary license - for those who cannot or do not want to adhere to AGPLv3 terms
#
# If you do not want to be bound by the AGPLv3 terms (such as releasing source code
# for modifications or network usage), you must acquire a proprietary license.
#
# See the LICENSE file for details.

# Define colors for better readability
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "Building TCP Fingerprint Monitor..."

# Check if required libraries are installed
if ! pkg-config --exists libbpf; then
    echo -e "${RED}Error: libbpf development package not found${NC}"
    echo "Please install libbpf-dev package"
    exit 1
fi

if ! pkg-config --exists ncurses; then
    echo -e "${RED}Error: ncurses development package not found${NC}"
    echo "Please install libncurses-dev package"
    exit 1
fi

# Compile with all warnings enabled and debug info
gcc -Wall -Wextra -g -o tcp_monitor tcp_monitor.c -lbpf -lncurses

# Check if compilation was successful
if [ $? -ne 0 ]; then
    echo -e "${RED}Build failed!${NC}"
    exit 1
else
    echo -e "${GREEN}Build successful!${NC}"
    echo "You can now run the monitor with: ./tcp_monitor <interface>"
    
    # Add important note about the bug fix in ebpf_filter.c
    echo -e "\n${BLUE}Important Note:${NC}"
    echo "For properly tracking new fingerprints, make sure ebpf_filter.c has the fix for"
    echo "counter initialization in the update_ip_stats function. Without this fix,"
    echo "new fingerprints may inherit hit counts from existing entries for the same IP."
    echo "To apply the fix, rebuild the firewall with 'make' and reload it."
fi

exit 0