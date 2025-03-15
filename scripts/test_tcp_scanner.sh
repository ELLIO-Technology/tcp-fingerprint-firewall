#!/bin/bash
#
# test_tcp_scanner.sh
#
# This software is dual-licensed under:
# - GNU Affero General Public License v3.0 (AGPLv3) - for those willing to comply with AGPLv3 terms
# - Proprietary license - for those who cannot or do not want to adhere to AGPLv3 terms
#
# If you do not want to be bound by the AGPLv3 terms (such as releasing source code
# for modifications or network usage), you must acquire a proprietary license.
#
# See the LICENSE file for details.


# Simple test script to send TCP SYN packets with different fingerprints
# Run this as root

# Find the root directory of the project
BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
FIREWALL="$BASE_DIR/build/tcp-firewall"
MONITOR="$BASE_DIR/build/tcp-monitor"

# Make sure the binaries exist
if [ ! -f "$FIREWALL" ]; then
    echo "Error: tcp-firewall binary not found at $FIREWALL"
    echo "Make sure you have built the project with 'make'"
    exit 1
fi

# Get the network interface from command line or try to detect it
INTERFACE=${1:-"$(ip route | grep default | awk '{print $5}')"}
if [ -z "$INTERFACE" ]; then
    echo "Error: Could not detect network interface. Please specify one as a parameter."
    echo "Usage: $0 <interface>"
    exit 1
fi

echo "Sending test TCP packets on interface $INTERFACE..."

# Check if hping3 is installed
if ! command -v hping3 &> /dev/null; then
    echo "hping3 not found. Please install it with 'sudo apt-get install hping3'"
    exit 1
fi

# Generate some synthetic traffic using hping3
echo "Sending Nmap-like SYN packet with window 1024..."
sudo hping3 -c 3 -S -p 80 --win 1024 8.8.8.8

# Wait a bit
sleep 2

# Check the filter results
echo "Checking filter results..."
sudo "$FIREWALL" "$INTERFACE" show --debug
sudo "$FIREWALL" "$INTERFACE" list --debug

echo "Test complete. To monitor traffic in real-time, run:"
echo "sudo $MONITOR $INTERFACE"