#!/bin/bash
#
# install_ubuntu.sh
#
# This software is dual-licensed under:
# - GNU Affero General Public License v3.0 (AGPLv3) - for those willing to comply with AGPLv3 terms
# - Proprietary license - for those who cannot or do not want to adhere to AGPLv3 terms
#
# If you do not want to be bound by the AGPLv3 terms (such as releasing source code
# for modifications or network usage), you must acquire a proprietary license.
#
# See the LICENSE file for details.


# Installation script for Fast Scanner Firewall on Ubuntu
# Installs dependencies, builds the firewall, and sets up the environment

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Check if run as root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Please run as root${NC}"
  exit 1
fi

echo -e "${GREEN}Installing Fast Scanner Firewall - TCP Fingerprint Firewall${NC}"

# Step 1: Install dependencies
echo -e "\n${YELLOW}Step 1: Installing dependencies...${NC}"
apt-get update
apt-get install -y clang llvm gcc make libbpf-dev libelf-dev 
apt-get install -y linux-headers-$(uname -r)
apt-get install -y linux-tools-common linux-tools-$(uname -r) bpfcc-tools

# Step 2: Check for BTF support
echo -e "\n${YELLOW}Step 2: Checking for BTF support...${NC}"
if [ -f "/sys/kernel/btf/vmlinux" ]; then
  echo -e "${GREEN}BTF support detected.${NC}"
else
  echo -e "${YELLOW}BTF support not detected. The firewall may still work in basic mode.${NC}"
  grep CONFIG_DEBUG_INFO_BTF /boot/config-$(uname -r)
fi

# Step 3: Build the firewall
echo -e "\n${YELLOW}Step 3: Building the firewall...${NC}"
make clean
make
make scripts

if [ ! -f "build/tcp-firewall" ] || [ ! -f "build/xdp_filter.o" ]; then
  echo -e "${RED}Build failed! Check for errors above.${NC}"
  exit 1
fi

echo -e "${GREEN}Build successful!${NC}"

# Step 4: Install to system
echo -e "\n${YELLOW}Step 4: Installing to /usr/local/bin...${NC}"
install -m 0755 build/tcp-firewall /usr/local/bin/
install -m 0644 build/xdp_filter.o /usr/local/bin/
install -m 0755 build/load_firewall.sh /usr/local/bin/
install -m 0755 build/test_firewall.sh /usr/local/bin/
install -m 0755 create_sample_fingerprints.sh /usr/local/bin/

# Update the script paths to point to the installed location
sed -i 's|./tcp-firewall|/usr/local/bin/tcp-firewall|g' /usr/local/bin/load_firewall.sh
sed -i 's|./tcp-firewall|/usr/local/bin/tcp-firewall|g' /usr/local/bin/test_firewall.sh
sed -i 's|./build/tcp-firewall|/usr/local/bin/tcp-firewall|g' /usr/local/bin/create_sample_fingerprints.sh
sed -i 's|^[ \t]*if [ ! -f "./build/tcp-firewall" ];|if [ ! -f "/usr/local/bin/tcp-firewall" ];|g' /usr/local/bin/create_sample_fingerprints.sh

echo -e "${GREEN}Installation complete!${NC}"

# Step 5: Show usage instructions
echo -e "\n${YELLOW}Usage instructions:${NC}"
echo -e "1. Load the firewall (replace eth0 with your interface):"
echo -e "   ${GREEN}sudo /usr/local/bin/load_firewall.sh eth0${NC}"
echo -e ""
echo -e "2. Test with common scanner patterns:"
echo -e "   ${GREEN}sudo /usr/local/bin/test_firewall.sh eth0${NC}"
echo -e ""
echo -e "3. Monitor matched IPs:"
echo -e "   ${GREEN}sudo /usr/local/bin/tcp-firewall eth0 show -c${NC}"
echo -e ""
echo -e "4. Unload when done:"
echo -e "   ${GREEN}sudo /usr/local/bin/tcp-firewall eth0 unload${NC}"
echo -e ""
echo -e "See README.md and USAGE.md for more information."