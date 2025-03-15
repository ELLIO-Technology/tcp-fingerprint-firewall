#!/bin/bash
#
# check_kernel_compat.sh
#
# This software is dual-licensed under:
# - GNU Affero General Public License v3.0 (AGPLv3) - for those willing to comply with AGPLv3 terms
# - Proprietary license - for those who cannot or do not want to adhere to AGPLv3 terms
#
# If you do not want to be bound by the AGPLv3 terms (such as releasing source code
# for modifications or network usage), you must acquire a proprietary license.
#
# See the LICENSE file for details.


# Script to check kernel compatibility for Fast Scanner Firewall
# This verifies that your kernel has the necessary features for XDP and eBPF

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo "Fast Scanner Firewall - Kernel Compatibility Check"
echo "------------------------------------------------"

# Check kernel version
KERNEL_VERSION=$(uname -r)
KERNEL_MAJOR=$(echo $KERNEL_VERSION | cut -d. -f1)
KERNEL_MINOR=$(echo $KERNEL_VERSION | cut -d. -f2)

echo -e "Kernel version: ${YELLOW}$KERNEL_VERSION${NC}"

# Verify kernel version meets minimum requirements
if [ "$KERNEL_MAJOR" -lt 5 ] || ([ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -lt 5 ]); then
  echo -e "${RED}⨯ Kernel version too old (5.5+ recommended)${NC}"
  echo -e "  The firewall may not work properly on this kernel."
  echo -e "  Consider upgrading your kernel for best results."
else
  echo -e "${GREEN}✓ Kernel version OK${NC}"
fi

# Check for BPF filesystem
if [ -d "/sys/fs/bpf" ]; then
  echo -e "${GREEN}✓ BPF filesystem mounted${NC}"
else
  echo -e "${RED}⨯ BPF filesystem not mounted${NC}"
  echo -e "  You need to mount the BPF filesystem:"
  echo -e "  sudo mount -t bpf bpf /sys/fs/bpf"
fi

# Check for BTF support
if [ -f "/sys/kernel/btf/vmlinux" ]; then
  echo -e "${GREEN}✓ BTF support available${NC}"
else
  echo -e "${YELLOW}⚠ BTF support not detected${NC}"
  echo -e "  The firewall will still work but with limitations."
  
  # Check if it's disabled in config
  if grep -q "CONFIG_DEBUG_INFO_BTF=y" /boot/config-$(uname -r) 2>/dev/null; then
    echo -e "  BTF is enabled in kernel config but not available."
  else
    echo -e "  BTF is not enabled in kernel config."
  fi
fi

# Check for XDP support
if lsmod | grep -q "^bpf" || grep -q "CONFIG_BPF=y" /boot/config-$(uname -r) 2>/dev/null; then
  echo -e "${GREEN}✓ BPF module available${NC}"
else
  echo -e "${RED}⨯ BPF module not loaded${NC}"
  echo -e "  Make sure BPF is enabled in your kernel."
fi

# Check if libbpf is installed
if ldconfig -p | grep -q "libbpf.so"; then
  echo -e "${GREEN}✓ libbpf library installed${NC}"
else
  echo -e "${RED}⨯ libbpf library not found${NC}"
  echo -e "  Install libbpf development packages:"
  echo -e "  sudo apt-get install libbpf-dev"
fi

# Check for required tools
echo -e "\nRequired tools:"
for tool in clang llvm-strip gcc make; do
  if command -v $tool &> /dev/null; then
    echo -e "  ${GREEN}✓ $tool${NC}"
  else
    echo -e "  ${RED}⨯ $tool not found${NC}"
  fi
done

# Summary
echo -e "\nSummary:"
echo -e "-------"
echo -e "The Fast Scanner Firewall requires:"
echo -e "1. Linux kernel 5.5+ (your version: $KERNEL_VERSION)"
echo -e "2. BPF and XDP support in the kernel"
echo -e "3. libbpf development libraries"
echo -e "4. clang and LLVM for compilation"

echo -e "\nRecommendation:"
if [ "$KERNEL_MAJOR" -lt 5 ] || ([ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -lt 5 ]); then
  echo -e "${RED}Your kernel may be too old. Consider upgrading for best results.${NC}"
elif ! ldconfig -p | grep -q "libbpf.so"; then
  echo -e "${RED}Missing libbpf. Install development packages before proceeding.${NC}"
else
  echo -e "${GREEN}Your system appears compatible. Proceed with installation.${NC}"
fi