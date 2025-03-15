# Installation Guide

This guide provides detailed instructions for installing TCP Fingerprint Firewall on your system.

## System Requirements

- Linux kernel 5.5 or newer
- For full functionality: kernel with BTF support (CONFIG_DEBUG_INFO_BTF)
- libbpf (version 0.7.0 or newer)
- For compiling: clang, LLVM, and kernel headers

## Prerequisites

Install the required packages:

### Debian/Ubuntu
```bash
sudo apt-get update
sudo apt-get install -y clang llvm gcc make libbpf-dev libelf-dev linux-headers-$(uname -r)
```

### Fedora/RHEL/CentOS
```bash
sudo dnf install -y clang llvm gcc make libbpf-devel elfutils-libelf-devel kernel-devel
```

### Arch Linux
```bash
sudo pacman -S clang llvm gcc make libbpf libelf linux-headers
```

## Installation Methods

### From Package (Recommended)

```bash
# Download the latest release
wget https://github.com/ellio-tech/tcp-fingerprint-firewall/releases/download/v2.0.0/tcp-fingerprint-firewall_2.0.0_amd64.deb

# Install with automatic dependency resolution
sudo apt update
sudo apt install -y ./tcp-fingerprint-firewall_2.0.0_amd64.deb
```

### From Source

```bash
# Clone the repository
git clone https://github.com/ellio-tech/tcp-fingerprint-firewall.git
cd tcp-fingerprint-firewall

# Build and install
make
sudo make install
```

### Using the Build Script (Most Complete Option)

```bash
# Clone the repository
git clone https://github.com/ellio-tech/tcp-fingerprint-firewall.git
cd tcp-fingerprint-firewall

# Build a package
./build_package.sh

# Install the package
sudo ./install_package.sh
```

## Verifying Installation

To verify that the installation was successful, run:

```bash
# If installed system-wide
tcp-firewall --help

# If built locally
./build/tcp-firewall --help
```

You should see the help text for the control program.

## Configuration

The firewall is configured through the command-line interface. Basic configuration steps:

```bash
# If installed system-wide
sudo tcp-firewall eth0 load
sudo tcp-firewall eth0 add "1024:::" DROP  # Nmap
sudo tcp-firewall eth0 add "65535:::" DROP  # ZMap

# If built locally
sudo ./build/tcp-firewall eth0 load
sudo ./build/tcp-firewall eth0 add "1024:::" DROP  # Nmap
sudo ./build/tcp-firewall eth0 add "65535:::" DROP  # ZMap
```

For more advanced configuration, see the [User Manual](user-manual.md).

## Troubleshooting

### BTF Issues

If you encounter errors related to BTF (BPF Type Format):

```
libbpf: BTF is required, but is missing or corrupted.
```

Run the diagnostic script:

```bash
./check_btf.sh
```

This will help you identify and fix BTF-related issues.

### Other Common Issues

1. **Error loading BPF object**: Ensure you have the correct kernel headers installed
2. **Permission denied**: Make sure you're running with sudo privileges
3. **Interface not found**: Check that you're using the correct interface name

For more troubleshooting tips, see the [Troubleshooting Guide](troubleshooting.md).

## Next Steps

After installation, you should:

1. Read the [User Manual](user-manual.md) to understand how to use the firewall
2. Configure your firewall with appropriate fingerprints
3. Set up monitoring to track scanning attempts

If you encounter any issues, please refer to our [Troubleshooting Guide](troubleshooting.md) or open an issue on GitHub.

## See Also

- [User Manual](user-manual.md) - Complete usage documentation
- [README](README.md) - Overview and quick start guide
- [Fingerprint Format](fingerprint-format.md) - Details on TCP fingerprint patterns
- [README-MONITOR](README-MONITOR.md) - TCP Fingerprint Monitor documentation