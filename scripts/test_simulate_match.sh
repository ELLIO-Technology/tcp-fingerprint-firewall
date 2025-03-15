#!/bin/bash
#
# test_simulate_match.sh
#
# This software is dual-licensed under:
# - GNU Affero General Public License v3.0 (AGPLv3) - for those willing to comply with AGPLv3 terms
# - Proprietary license - for those who cannot or do not want to adhere to AGPLv3 terms
#
# If you do not want to be bound by the AGPLv3 terms (such as releasing source code
# for modifications or network usage), you must acquire a proprietary license.
#
# See the LICENSE file for details.


# Simulate a matched packet by directly updating the BPF maps

# Find the root directory of the project
BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
FIREWALL="$BASE_DIR/build/tcp-firewall"
MONITOR="$BASE_DIR/build/tcp-monitor"

# Check if BPF filesystem is mounted
if [ ! -d "/sys/fs/bpf" ]; then
    echo "BPF filesystem not mounted. Run: sudo mount -t bpf bpf /sys/fs/bpf"
    exit 1
fi

# Check if the maps exist
if [ ! -f "/sys/fs/bpf/blocked_ips" ]; then
    echo "BPF maps not found. Make sure the filter is loaded using:"
    echo "sudo $FIREWALL <interface> load"
    exit 1
fi

# Check for bpftool
if ! command -v bpftool &> /dev/null; then
    echo "bpftool not found. Please install it with 'sudo apt-get install linux-tools-common linux-tools-generic'"
    exit 1
fi

# Get the network interface from command line or try to detect it
INTERFACE=${1:-"$(ip route | grep default | awk '{print $5}')"}
if [ -z "$INTERFACE" ]; then
    echo "Could not detect network interface. Will use 'eth0' as default."
    INTERFACE="eth0"
    echo "Note: You can specify an interface: $0 <interface>"
fi

# Use bpftool to update the maps directly
echo "Simulating a matched packet with window size 1024..."

# Create a temporary file with the IP stats structure
cat > /tmp/ip_stats.bin << EOF
{
  "timestamp": 123456789,
  "count": 1,
  "window_size": 1024,
  "mss": 0,
  "window_scale": 0,
  "fingerprint_id": 0
}
EOF

# Use bpftool to update the map
echo "Adding a simulated match for IP 8.8.8.8 (134744072 in decimal)..."
sudo bpftool map update name blocked_ips key hex 08 08 08 08 value file /tmp/ip_stats.bin

# Update the config map to increment the match counter
echo "Updating the config map..."
sudo bpftool map update name config_map key hex 00 00 00 00 value hex 01 00 00 00 01 00 00 00

echo "Done! Check the matches with:"
echo "sudo $FIREWALL $INTERFACE show --debug"
echo "Or view in real-time with:"
echo "sudo $MONITOR $INTERFACE"