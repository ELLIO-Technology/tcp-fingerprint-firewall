# User Manual

This manual provides comprehensive information on how to use TCP Fingerprint Firewall effectively.

## Table of Contents

- [Basic Commands](#basic-commands)
- [Loading and Unloading](#loading-and-unloading)
- [Managing Fingerprints](#managing-fingerprints)
- [Monitoring](#monitoring)
- [Advanced Usage](#advanced-usage)
- [Example Scenarios](#example-scenarios)

## Basic Commands

TCP Fingerprint Firewall is controlled through the `tcp-firewall` command-line utility. Here's a quick reference of the most common commands:

```bash
# Show help
tcp-firewall --help

# Load the firewall on an interface
sudo tcp-firewall eth0 load

# Show matched IPs
sudo tcp-firewall eth0 show

# Add a fingerprint
sudo tcp-firewall eth0 add "1024:::" DROP

# List configured fingerprints
sudo tcp-firewall eth0 list

# Unload the firewall
sudo tcp-firewall eth0 unload
```

## Loading and Unloading

### Loading the Firewall

To load the firewall on a network interface:

```bash
sudo tcp-firewall eth0 load
```

By default, this loads the XDP program with a default action of PASS for packets not matching any fingerprint.

You can specify a different default action:

```bash
sudo tcp-firewall eth0 load --default-action DROP
```

### Unloading the Firewall

To unload the firewall:

```bash
sudo tcp-firewall eth0 unload
```

This removes the XDP program from the interface and cleans up all BPF maps.

## Managing Fingerprints

### Adding Fingerprints

To add a fingerprint:

```bash
sudo tcp-firewall eth0 add "<pattern>" <action>
```

Where:
- `<pattern>` is a MuonFP-style fingerprint pattern (see [Fingerprint Format](fingerprint-format.md))
- `<action>` is either DROP or PASS

Examples:

```bash
# Block Nmap scanner
sudo tcp-firewall eth0 add "1024:::" DROP

# Block ZMap scanner
sudo tcp-firewall eth0 add "65535:::" DROP

# Block packets with specific TCP options pattern
sudo tcp-firewall eth0 add "65535:2-4-8-1-3:1460:7" DROP

# Block any packet without TCP options
sudo tcp-firewall eth0 add "*:::" DROP
```

### Loading Fingerprints from File

You can create a script to load multiple fingerprints from a CSV file:

```bash
#!/bin/bash
# fingerprints.sh - Load fingerprints from CSV file
interface="$1"
csv_file="$2"
action="$3"

if [ -z "$interface" ] || [ -z "$csv_file" ] || [ -z "$action" ]; then
    echo "Usage: $0 <interface> <csv_file> <action>"
    exit 1
fi

while IFS= read -r pattern; do
    # Skip empty lines and comments
    if [ -n "$pattern" ] && [ "${pattern:0:1}" != "#" ]; then
        echo "Adding: $pattern"
        sudo tcp-firewall "$interface" add "$pattern" "$action"
    fi
done < "$csv_file"

# Example usage:
# ./fingerprints.sh eth0 fingerprints.csv DROP
```

The CSV file should have one fingerprint pattern per line.

### Listing Fingerprints

To list all configured fingerprints:

```bash
sudo tcp-firewall eth0 list
```

This shows the ID, components, action, and match count for each fingerprint.

### Removing Fingerprints

To remove a fingerprint by ID:

```bash
sudo tcp-firewall eth0 remove <id>
```

Replace `<id>` with the fingerprint ID shown in the list output.

### Clearing All Fingerprints

To clear all fingerprints and matched IPs:

```bash
sudo tcp-firewall eth0 clear
```

This removes all fingerprint rules and clears all tracking data.

## Monitoring

### Showing Matched IPs

To display IPs that matched fingerprints:

```bash
sudo tcp-firewall eth0 show
```

For continuous monitoring:

```bash
sudo tcp-firewall eth0 show -c
```

Press Ctrl+C to stop continuous monitoring.

### Fingerprint Statistics

To view statistics for each fingerprint, use the list command:

```bash
sudo tcp-firewall eth0 list
```

This shows how many packets matched each fingerprint.

## Advanced Usage

### Debug Mode

For troubleshooting or detailed information, use debug mode:

```bash
sudo tcp-firewall eth0 --debug show
```

### Working with Multiple Interfaces

You can run TCP Fingerprint Firewall on multiple interfaces simultaneously:

```bash
sudo tcp-firewall eth0 load
sudo tcp-firewall eth1 load
```

Each interface maintains its own set of fingerprints and configuration.

## Example Scenarios

### Basic Scanner Protection

```bash
# Load the firewall
sudo tcp-firewall eth0 load

# Block common scanners
sudo tcp-firewall eth0 add "1024:::" DROP  # Nmap
sudo tcp-firewall eth0 add "65535:::" DROP  # ZMap
sudo tcp-firewall eth0 add "512:::" DROP    # Modified ZMap

# Monitor for matches
sudo tcp-firewall eth0 show -c
```

### Advanced Fingerprinting

```bash
# Load the firewall
sudo tcp-firewall eth0 load

# Create a fingerprint database script (see "Loading Fingerprints from File" section)
# Then run it to load multiple fingerprints
./fingerprints.sh eth0 fingerprints.csv DROP

# Add a custom fingerprint for a specific OS
sudo tcp-firewall eth0 add "65535:2-4-8-1-3:1460:7" DROP

# Monitor for matches
sudo tcp-firewall eth0 show -c
```

### Selective Blocking

```bash
# Load the firewall with default PASS
sudo tcp-firewall eth0 load

# Block specific patterns
sudo tcp-firewall eth0 add "1024:::" DROP  # Nmap
sudo tcp-firewall eth0 add "*:2:*:*" PASS   # Allow any with only MSS option
sudo tcp-firewall eth0 add "*:::" DROP     # Block any with no options
```

For more examples and advanced usage scenarios, see the related documentation files.

## See Also

- [README](README.md) - Overview and quick start guide
- [Installation Guide](installation.md) - Instructions for installing the software
- [Fingerprint Format](fingerprint-format.md) - Details on TCP fingerprint patterns
- [Troubleshooting Guide](troubleshooting.md) - Solutions for common issues
- [README-MONITOR](README-MONITOR.md) - TCP Fingerprint Monitor documentation
- [USAGE](USAGE.md) - Quick reference guide