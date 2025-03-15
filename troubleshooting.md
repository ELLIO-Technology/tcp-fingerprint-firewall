# Troubleshooting Guide

This guide helps you diagnose and resolve common issues with TCP Fingerprint Firewall.

## BTF-Related Issues

### Symptom: "BTF is required, but is missing or corrupted"

This error occurs when the kernel doesn't have BTF support or the required information is not available.

#### Diagnosis

Run the check_btf.sh script:

```bash
./check_btf.sh
```

#### Solutions

1. **Install kernel headers**:
   ```bash
   sudo apt-get install linux-headers-$(uname -r)
   ```

2. **Verify BTF support in your kernel**:
   ```bash
   grep CONFIG_DEBUG_INFO_BTF /boot/config-$(uname -r)
   ```
   If the output is not `CONFIG_DEBUG_INFO_BTF=y`, you may need a newer kernel.

3. **Update your kernel**:
   Consider updating to a distribution with kernel 5.5 or newer that includes BTF support.

## Loading Issues

### Symptom: "Failed to open BPF object"

#### Diagnosis

Check if the XDP object file exists:

```bash
ls -la /usr/local/bin/xdp_filter.o
```

#### Solutions

1. **Specify the correct path**:
   ```bash
   sudo tcp-firewall --debug eth0 load
   ```
   The debug output will show which paths it's searching.

2. **Rebuild the object file**:
   ```bash
   cd /path/to/tcp-fingerprint-firewall
   make
   sudo make install
   ```

### Symptom: "Interface already has an XDP program attached"

#### Solutions

1. **Detach existing program**:
   ```bash
   sudo ip link set dev eth0 xdp off
   ```

2. **Force unload existing program**:
   ```bash
   sudo tcp-firewall eth0 unload
   ```

## Permission Issues

### Symptom: "Permission denied" errors

#### Solutions

1. **Run with sudo**:
   ```bash
   sudo tcp-firewall eth0 load
   ```

2. **Check BPF filesystem**:
   ```bash
   sudo mount -t bpf bpf /sys/fs/bpf
   ```

3. **Verify file permissions**:
   ```bash
   ls -la /usr/local/bin/tcp-*
   sudo chmod 755 /usr/local/bin/tcp-firewall
   sudo chmod 644 /usr/local/bin/xdp_filter.o
   ```

## Map Issues

### Symptom: "Failed to open blocked_ips map"

#### Solutions

1. **Reload the program**:
   ```bash
   sudo tcp-firewall eth0 unload
   sudo tcp-firewall eth0 load
   ```

2. **Clean up manually**:
   ```bash
   sudo rm -f /sys/fs/bpf/blocked_ips /sys/fs/bpf/tcp_fingerprints /sys/fs/bpf/config_map
   sudo tcp-firewall eth0 load
   ```

## Fingerprint Issues

### Symptom: No packets being dropped

#### Diagnosis

Check if your fingerprints are loaded:

```bash
sudo tcp-firewall eth0 list
```

#### Solutions

1. **Add fingerprints**:
   ```bash
   sudo tcp-firewall eth0 add "1024:::" DROP
   ```

2. **Check default action**:
   ```bash
   sudo tcp-firewall eth0 unload
   sudo tcp-firewall eth0 load --default-action DROP
   ```

3. **Verify with test traffic**:
   ```bash
   # On another system
   nmap -sS target_ip
   
   # Check for matches
   sudo tcp-firewall eth0 show
   ```

## Performance Issues

### Symptom: High CPU usage

#### Solutions

1. **Ensure XDP hardware offload if available**:
   ```bash
   sudo tcp-firewall eth0 unload
   sudo tcp-firewall eth0 load -o /path/to/custom/xdp_filter.o
   ```

2. **Limit the number of fingerprints**:
   Remove unnecessary fingerprints to improve matching performance.

## Kernel or Compatibility Issues

### Symptom: "Unsupported operation" or similar kernel errors

#### Diagnosis

Check your kernel version:

```bash
uname -r
```

#### Solutions

1. **Update your kernel** to at least 5.5 or newer.

2. **Ensure your kernel supports BPF features**:
   Consider updating to kernel 5.5 or newer for best compatibility.

## Recovery from Crashes

If the system crashes or reboots:

1. **Clean up BPF maps**:
   ```bash
   sudo rm -f /sys/fs/bpf/blocked_ips /sys/fs/bpf/tcp_fingerprints /sys/fs/bpf/config_map
   ```

2. **Remove XDP program from interface**:
   ```bash
   sudo ip link set dev eth0 xdp off
   ```

3. **Reload the firewall**:
   ```bash
   sudo tcp-firewall eth0 load
   ```

## Getting Help

If you continue to experience issues:

1. **Enable debug mode**:
   ```bash
   sudo tcp-firewall --debug eth0 command
   ```

2. **Check kernel logs**:
   ```bash
   sudo dmesg | grep bpf
   ```

3. **Open an issue** on our GitHub repository with:
   - Detailed error messages
   - Output of `sudo tcp-firewall --debug eth0 command`
   - Output of `uname -a`
   - Output of `./scripts/check_btf.sh`

## See Also

- [Installation Guide](installation.md) - Instructions for installing the software
- [User Manual](user-manual.md) - Complete usage documentation
- [README](README.md) - Overview and quick start guide
- [Fingerprint Format](fingerprint-format.md) - Details on TCP fingerprint patterns