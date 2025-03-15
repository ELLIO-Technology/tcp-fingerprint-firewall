# TCP Fingerprint Firewall Usage Guide

## License

This software is dual-licensed under:
- [GNU Affero General Public License v3.0](https://www.gnu.org/licenses/agpl-3.0.en.html) (AGPLv3) - for those willing to comply with AGPLv3 terms including source code release requirements
- Proprietary license - for those who cannot or do not want to adhere to AGPLv3 terms

If you do not want to be bound by the AGPLv3 terms (such as releasing source code for modifications or network usage), you must acquire a proprietary license.

For details, see the LICENSE file.

This document provides a quick reference for using the TCP fingerprint-based firewall.

## Basic Commands

| Command | Description |
|---------|-------------|
| `tcp-firewall <interface> load` | Load the firewall on an interface |
| `tcp-firewall <interface> unload` | Unload the firewall |
| `tcp-firewall <interface> show` | Show matched IPs |
| `tcp-firewall <interface> show -c` | Show matched IPs continuously |
| `tcp-firewall <interface> list` | List configured fingerprints |
| `tcp-firewall <interface> add <pattern> <action>` | Add a fingerprint pattern |
| `tcp-firewall <interface> remove <id>` | Remove a fingerprint by ID |
| `tcp-firewall <interface> clear` | Clear all fingerprints and matched IPs |

## Options

| Option | Description |
|--------|-------------|
| `-d, --debug` | Enable debug output |
| `-c, --continuous` | Continuous monitoring mode |
| `-a, --default-action <action>` | Set default action (DROP/PASS) |
| `-o, --obj <filename>` | Specify custom BPF object file path |

## eBPF/XDP Management Commands

These commands are useful for managing XDP programs on network interfaces:

| Command | Description |
|---------|-------------|
| `sudo ip link set dev <interface> xdp off` | Remove XDP program from interface |
| `sudo ip link set dev <interface> xdp object <file.o> section <section_name>` | Attach XDP program manually |
| `sudo ip link show dev <interface>` | Check if XDP program is attached to interface |
| `sudo bpftool prog list` | List all loaded BPF programs |
| `sudo bpftool map list` | List all BPF maps |
| `sudo bpftool map dump name <map_name>` | Dump contents of a BPF map |
| `sudo mount -t bpf bpf /sys/fs/bpf` | Mount BPF filesystem (if not already mounted) |
| `sudo rm -f /sys/fs/bpf/blocked_ips /sys/fs/bpf/tcp_fingerprints /sys/fs/bpf/config_map` | Clean up BPF maps (for recovery) |

### Advanced XDP Options

| Command | Description |
|---------|-------------|
| `sudo ip link set dev <interface> xdp drv object <file.o> section <section_name>` | Load XDP in driver mode (default) |
| `sudo ip link set dev <interface> xdp hw object <file.o> section <section_name>` | Load XDP with hardware offloading (if supported) |
| `sudo ip link set dev <interface> xdp skb object <file.o> section <section_name>` | Load XDP in generic/SKB mode (slower, for unsupported drivers) |
| `sudo ip link set dev <interface> xdpgeneric off` | Remove generic XDP program |
| `sudo ip link set dev <interface> xdpdrv off` | Remove driver-mode XDP program |
| `sudo ip link set dev <interface> xdpoffload off` | Remove hardware-offloaded XDP program |

### Hardware Offload Support

Check if your network card supports XDP hardware offload:

```bash
# List network interfaces with XDP capabilities
ethtool -k <interface> | grep xdp

# Check for XDP_FLAGS_HW_MODE support (1 means supported)
sudo bpftool feature probe xdp | grep "XDP hardware offload"

# Check driver compatibility for XDP offload
sudo ethtool -i <interface>
```

Commonly supported drivers for XDP offload: Netronome (nfp), Mellanox (mlx5), Intel (ice, i40e).

## Fingerprint Patterns

Fingerprints follow the format: `window_size:options:mss:window_scale`

| Field | Description | Examples |
|-------|-------------|----------|
| window_size | TCP window size | `1024`, `65535`, `*` (any) |
| options | TCP options kind | Empty (none), `2` (MSS), `*` (any) |
| mss | Maximum Segment Size | `1460`, Empty (none), `*` (any) |
| window_scale | Window scaling factor | `7`, Empty (none), `*` (any) |

### Common Patterns

| Pattern | Description | Action |
|---------|-------------|--------|
| `1024:::` | Nmap scanner | DROP |
| `65535:::` | ZMap scanner | DROP |
| `*:2:1460:*` | Nmap with options | DROP |

## Example Usage

```bash
# Load the firewall on interface eth0
sudo ./build/tcp-firewall eth0 load

# Add Nmap scanner fingerprint
sudo ./build/tcp-firewall eth0 add "1024:::" DROP

# Add ZMap scanner fingerprint
sudo ./build/tcp-firewall eth0 add "65535:::" DROP

# Show matched IPs continuously
sudo ./build/tcp-firewall eth0 show -c

# Unload the firewall when done
sudo ./build/tcp-firewall eth0 unload
```

## Test Scripts

Two test scripts are provided for convenience:

1. `test_firewall.sh`: Interactive testing with step-by-step guidance
   ```bash
   sudo ./build/test_firewall.sh eth0
   ```

2. `create_sample_fingerprints.sh`: Quick setup with common fingerprints
   ```bash
   sudo ./create_sample_fingerprints.sh eth0
   ```

## Troubleshooting

1. Always run commands with `sudo` or as root
2. If the program fails to load, try enabling debug mode:
   ```bash
   sudo ./build/tcp-firewall eth0 load --debug
   ```
3. Check that the interface name is correct and exists
4. Verify that the kernel supports XDP and eBPF (kernel 5.5+)
5. Make sure libbpf is installed and up to date

### Testing with Loopback Interface

The loopback interface (lo) can be used for testing:

```bash
# Enable XDP on loopback interface
sudo ip link set dev lo xdp object build/xdp_filter.o sec xdp

# Check if it loaded properly
sudo ip link show dev lo | grep xdp

# Generate some test traffic
curl 127.0.0.1:80
nc -zv 127.0.0.1 80

# Remove XDP from loopback when done
sudo ip link set dev lo xdp off
```

Note: The loopback interface requires kernel 5.8+ for XDP support. For older kernels, use a real interface or a virtual one like veth.

### Debugging XDP Programs

For troubleshooting XDP programs:

```bash
# View detailed logs
sudo bpftool prog tracelog

# Check for verifier errors (most common with eBPF programs)
sudo dmesg | grep bpf

# Get the raw BPF instructions (helpful for deep debugging)
sudo bpftool prog dump xlated id <prog_id>

# Check pinned maps in the BPF filesystem
sudo ls -la /sys/fs/bpf/
```

## Advanced Usage

### Working with Multiple Fingerprints

You can combine multiple fingerprints for comprehensive protection:

```bash
# Add fingerprints for various scanner types
sudo ./build/tcp-firewall eth0 add "1024:::" DROP    # Classic Nmap
sudo ./build/tcp-firewall eth0 add "65535:::" DROP   # ZMap
sudo ./build/tcp-firewall eth0 add "*:2:1460:*" DROP # Nmap with MSS option
```

### Debugging and Monitoring

For troubleshooting, you can enable debug output and monitor matches:

```bash
# Enable debug output when loading
sudo ./build/tcp-firewall eth0 load --debug

# Monitor matches in real-time
sudo ./build/tcp-firewall eth0 show -c
```

## Implementation Notes

The current implementation is optimized for eBPF verifier compatibility:

1. Supports up to 64 unique fingerprints
2. Enhanced TCP options parsing with sequence matching support
3. Only processes SYN packets (initial connection attempts)
4. Support for complex fingerprint patterns with full option sequence matching

## See Also

- [README](README.md) - Overview and quick start guide
- [Installation Guide](installation.md) - Instructions for installing the software
- [User Manual](user-manual.md) - Complete usage documentation
- [Fingerprint Format](fingerprint-format.md) - Details on TCP fingerprint patterns
- [Troubleshooting Guide](troubleshooting.md) - Solutions for common issues
- [README-MONITOR](README-MONITOR.md) - TCP Fingerprint Monitor documentation