#!/bin/bash
#
# create_sample_fingerprints.sh
#
# This software is dual-licensed under:
# - GNU Affero General Public License v3.0 (AGPLv3) - for those willing to comply with AGPLv3 terms
# - Proprietary license - for those who cannot or do not want to adhere to AGPLv3 terms
#
# If you do not want to be bound by the AGPLv3 terms (such as releasing source code
# for modifications or network usage), you must acquire a proprietary license.
#
# See the LICENSE file for details.


# Helper script to create sample fingerprint definitions
# This creates examples for common scanners and devices

INTERFACE=$1

if [ -z "$INTERFACE" ]; then
  echo "Usage: $0 <interface>"
  echo "Example: $0 eth0"
  exit 1
fi

# Check if the control binary is available
if [ ! -f ./build/tcp-firewall ]; then
  echo "Error: tcp-firewall not found. Please run 'make' first."
  exit 1
fi

# Verify the firewall is loaded
echo "Loading firewall on $INTERFACE..."
sudo ./build/tcp-firewall $INTERFACE load

echo "Adding sample fingerprint patterns..."

# Common scanner fingerprints
echo "Adding scanner fingerprints..."
sudo ./build/tcp-firewall $INTERFACE add "1024:::" DROP  # Nmap basic (fingerprint ID 0)
sudo ./build/tcp-firewall $INTERFACE add "65535:::" DROP  # ZMap (fingerprint ID 1)
sudo ./build/tcp-firewall $INTERFACE add "*:2:1460:*" DROP  # Nmap with options (fingerprint ID 2)

echo "Sample fingerprints created successfully!"
echo "Use 'sudo ./build/tcp-firewall $INTERFACE list' to view them."