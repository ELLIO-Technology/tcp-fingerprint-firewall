#!/bin/bash
#
# install_and_build.sh
#
# This software is dual-licensed under:
# - GNU Affero General Public License v3.0 (AGPLv3) - for those willing to comply with AGPLv3 terms
# - Proprietary license - for those who cannot or do not want to adhere to AGPLv3 terms
#
# If you do not want to be bound by the AGPLv3 terms (such as releasing source code
# for modifications or network usage), you must acquire a proprietary license.
#
# See the LICENSE file for details.

#
# TCP Fingerprint Firewall - Installation and Build Script
# This script installs all required dependencies and builds the firewall components
#

# Terminal colors for better user feedback
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Set working directory to the root of the project
cd "$(dirname "$0")/.." || {
    echo -e "${RED}Error: Could not navigate to project root directory${NC}"
    exit 1
}

echo -e "${BLUE}===== TCP Fingerprint Firewall - Installation and Build Script =====${NC}"
echo ""

# Check if we're running as root (needed for package installation)
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}Warning: Not running as root. Package installation may fail.${NC}"
    echo -e "Consider running with sudo if you need to install dependencies."
    echo ""
fi

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Step 1: Check for and install dependencies
echo -e "${BLUE}Step 1: Checking and installing dependencies...${NC}"

# List of required packages
PACKAGES=(
    "build-essential"
    "clang"
    "llvm"
    "libelf-dev"
    "libbpf-dev"
    "libncurses-dev"
    "pkg-config"
)

# Check for package manager
if command_exists apt-get; then
    PM="apt-get"
    PM_INSTALL="apt-get install -y"
elif command_exists dnf; then
    PM="dnf"
    PM_INSTALL="dnf install -y"
elif command_exists yum; then
    PM="yum"
    PM_INSTALL="yum install -y"
elif command_exists pacman; then
    PM="pacman"
    PM_INSTALL="pacman -S --noconfirm"
else
    echo -e "${YELLOW}Warning: Unsupported package manager. You may need to install dependencies manually.${NC}"
    echo "Required packages: ${PACKAGES[*]}"
    echo ""
fi

# Install packages if package manager is available
if [ -n "$PM" ]; then
    # Check for updates first
    echo "Updating package lists..."
    $PM update >/dev/null 2>&1
    
    # Install each package if not already installed
    for pkg in "${PACKAGES[@]}"; do
        if ! $PM list installed "$pkg" &>/dev/null && ! $PM list "$pkg" &>/dev/null; then
            echo "Installing $pkg..."
            $PM_INSTALL "$pkg"
            if [ $? -ne 0 ]; then
                echo -e "${RED}Failed to install $pkg. Please install it manually.${NC}"
            fi
        else
            echo -e "${GREEN}$pkg is already installed.${NC}"
        fi
    done
fi

# Step 2: Check BPF mount status
echo -e "\n${BLUE}Step 2: Checking BPF filesystem...${NC}"
./scripts/check_bpf_mount.sh
if [ $? -ne 0 ]; then
    echo -e "${YELLOW}Warning: BPF filesystem is not mounted. Loading the firewall may fail.${NC}"
    echo "You can run 'sudo mount -t bpf bpf /sys/fs/bpf/' to mount it."
fi

# Step 3: Check kernel compatibility
echo -e "\n${BLUE}Step 3: Checking kernel compatibility...${NC}"
./scripts/check_kernel_compat.sh
if [ $? -ne 0 ]; then
    echo -e "${YELLOW}Warning: Your kernel may not fully support all eBPF features.${NC}"
    echo "You may need to update your kernel for better compatibility."
fi

# Step 4: Check BTF information
echo -e "\n${BLUE}Step 4: Checking BTF support...${NC}"
./scripts/check_btf.sh
if [ $? -ne 0 ]; then
    echo -e "${YELLOW}Warning: BTF support is not available. Kernel 5.5+ is recommended.${NC}"
fi

# Step 5: Clean any previous build
echo -e "\n${BLUE}Step 5: Cleaning previous build...${NC}"
make clean
if [ $? -ne 0 ]; then
    echo -e "${RED}Error: Make clean failed. Check for errors.${NC}"
    exit 1
fi

# Step 6: Build all components
echo -e "\n${BLUE}Step 6: Building all components...${NC}"
make all
if [ $? -ne 0 ]; then
    echo -e "${RED}Error: Build failed. Check for errors above.${NC}"
    exit 1
fi

# Step 7: Creating load scripts
echo -e "\n${BLUE}Step 7: Creating load scripts...${NC}"
make scripts
if [ $? -ne 0 ]; then
    echo -e "${YELLOW}Warning: Failed to create load scripts. Check Makefile.${NC}"
fi

# Success message
echo -e "\n${GREEN}===== Build completed successfully! =====${NC}"
echo -e "The TCP Fingerprint Firewall has been built and is ready to use."
echo ""
echo -e "${BLUE}Usage:${NC}"
echo "1. Load the firewall:"
echo "   sudo ./build/load_firewall.sh <interface>"
echo ""
echo "2. Monitor TCP fingerprints:"
echo "   sudo ./build/tcp-monitor <interface>"
echo ""
echo -e "${YELLOW}Note:${NC} You need root privileges to load the firewall."
echo -e "For more information, check the README.md and documentation in the docs/ directory.\n"

exit 0