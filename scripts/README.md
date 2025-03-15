# TCP Fingerprint Firewall - Scripts Directory

This directory contains various helper scripts for building, testing, and managing the TCP Fingerprint Firewall.

## Main Scripts

- **install_and_build.sh**: Main installation and build script. This script checks for dependencies, installs required packages, and builds all components of the firewall. Run this first.

## Build Scripts

- **build_monitor.sh**: Builds just the monitor component.

## System Check Scripts

- **check_bpf_mount.sh**: Verifies that the BPF filesystem is properly mounted.
- **check_btf.sh**: Checks if your kernel supports BTF (BPF Type Format) information.
- **check_kernel_compat.sh**: Checks if your kernel is compatible with the eBPF features used.
- **install_ubuntu.sh**: Installs required dependencies on Ubuntu systems.

## Testing Scripts

- **create_sample_fingerprints.sh**: Creates sample fingerprint patterns for testing.
- **test_tcp_scanner.sh**: Tests TCP scanner detection.
- **test_simulate_match.sh**: Simulates fingerprint matching.
- **test_document_patterns.sh**: Documents fingerprint patterns.

## Usage

To install and build the entire project in one step:

```bash
sudo ./scripts/install_and_build.sh
```

After building the project, the firewall can be loaded using:

```bash
sudo ./build/load_firewall.sh <interface>
```

To monitor TCP fingerprints in real-time:

```bash
sudo ./build/tcp-monitor <interface>
```