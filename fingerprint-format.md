# TCP Fingerprint Format

TCP Fingerprint Firewall uses a MuonFP - four-component fingerprint to identify and filter TCP packets. This document explains the format and how to create effective fingerprints.

## Format Overview

A TCP fingerprint has the following format:

```
window_size:options:mss:window_scale
```

Each component represents a different aspect of the TCP header:

1. **window_size**: The TCP window size value
2. **options**: TCP options present in the header
3. **mss**: Maximum Segment Size value
4. **window_scale**: Window scale factor

## Component Details

### Window Size

The window size is a 16-bit value from the TCP header. Examples:
- `1024`: Exact window size (typical for Nmap SYN scan or Masscan)
- `65535`: Exact window size (typical for ZMap)
- `*`: Wildcard (matches any window size)

### TCP Options

The options component represents which TCP options are present and in what order:
- `2-4-8-1-3`: Specific options sequence (option types 2, 4, 8, 1, 3 in that order)
- `2`: Single option (ONLY option type 2 is present, no others)
- `` (empty): No TCP options present
- `*`: Wildcard (matches any options configuration)

**New Feature: Complex Option Sequence Matching**
The firewall now supports TCP option sequence matching using the hyphenated format (e.g., `2-4-8-1-3`).
When this format is used, the firewall will validate that all specified option types are present in the TCP header, though it doesn't verify they appear in the exact sequence specified.

Common TCP option types:
- `0`: End of option list
- `1`: No-operation
- `2`: Maximum Segment Size (MSS)
- `3`: Window Scale
- `4`: SACK permitted
- `8`: Timestamps

### MSS (Maximum Segment Size)

The MSS value from option type 2:
- `1460`: Specific MSS value
- `` (empty): No MSS option present
- `*`: Wildcard (matches any MSS value)

### Window Scale

The window scale value from option type 3:
- `7`: Specific window scale factor
- `` (empty): No window scale option present
- `*`: Wildcard (matches any window scale value)

## Wildcards and Empty Fields

The fingerprint system supports two special values:

1. **Wildcard (`*`)**: Matches any value for this component
2. **Empty field (``)**: Requires the absence of this feature

These can be combined to create flexible matching patterns.

## Examples

### Common Scanner Fingerprints

```
1024:::        # Nmap (window size 1024, no options)
65535:::       # ZMap (window size 65535, no options)
1024:2:1460:   # Nmap with MSS option
```

### Operating System Fingerprints

```
64240:2-1-3-1-1-4:1460:8          # Windows 10
65535:2-1-3-1-1-8-4-0-0:1460:6    # macOS/iOS
65535:2-4-8-1-3:1460:7            # Ubuntu 22.04
```

### Pattern Matching with Wildcards

```
*:::            # Any packet without TCP options
*:2:*:*         # Any packet with only MSS option
1024:*:*:*      # Any packet with window size 1024
*:*:1460:*      # Any packet with MSS value 1460
```

## Creating Custom Fingerprints

To create custom fingerprints:

1. Capture TCP SYN packets from the target device/tool
2. Extract the TCP header information
3. Format as `window_size:options:mss:window_scale`

or use awesome [MuonFP](https://github.com/sundruid/muonfp) and save yourself a headache.

## Priority and Conflicts

When multiple fingerprints could match a packet:

1. More specific fingerprints (fewer wildcards) take precedence
2. Earlier-added fingerprints take precedence when specificity is equal

## Performance Considerations

- Fingerprints with no wildcards are matched faster
- Window size is checked first for performance
- Using wildcards increases flexibility but may slightly impact performance
- Complex option sequences (like `2-4-8-1-3`) are efficiently matched using bitmap operations

## Implementation Details

The new implementation provides enhanced handling of complex TCP option sequences:

1. **Bitmap Option Detection**: All TCP options are tracked in a 64-bit bitmap where bit position corresponds to option type
2. **Sequence Storage**: For complex patterns (like `2-4-8-1-3`), the sequence is stored in an array for exact matching
3. **Verifier-Friendly**: The implementation is designed to be compatible with the BPF verifier's constraints
4. **Extended Sequence Support**: Up to 8 distinct options can be matched in a sequence (though the structure supports storing up to 16)
5. **Increased Capacity**: The firewall now supports up to 64 unique fingerprints (IDs 0-63)
6. **Duplicate Detection**: Identical fingerprints are automatically detected and not added twice
7. **Action Updates**: Adding an existing pattern with a different action will update the action
8. **Multiple Fingerprints per IP**: The firewall now stores and displays multiple distinct fingerprints from the same source IP address
9. **Improved Display**: The status display shows up to 5 fingerprints per source IP, with the most recent matches first

## Creating a Fingerprint Database

You can create a CSV file with common fingerprints and load it by adding each fingerprint individually. For example, if you create a file named `fingerprints.csv` with one fingerprint per line:

```
1024:::
65535:::
65535:2-4-8-1-3:1460:7
```

You can load it with a script:

```bash
#!/bin/bash
while IFS= read -r pattern; do
    sudo tcp-firewall eth0 add "$pattern" DROP
done < fingerprints.csv
```

## Further Reading

For more information on TCP fingerprinting techniques:
- [MuonFP Project](https://github.com/sundruid/muonfp)
- [There is No Such Thing as a 'Benign' Internet Scanner](https://www.kenwebster.com/index.php/2025/01/29/there-is-no-such-thing-as-a-benign-internet-scanner/)
- [IP Blocking vs TCP Fingerprint Blocking: How to Use and Combine Them](https://blog.ellio.tech/ip-blocking-vs-tcp-fingerprint-blocking-how-to-use-and-combine-them/)

## See Also

- [User Manual](user-manual.md) - Complete usage documentation
- [README](README.md) - Overview and quick start guide
- [Troubleshooting Guide](troubleshooting.md) - Solutions for common issues
- [README-MONITOR](README-MONITOR.md) - TCP Fingerprint Monitor documentation

