/* 
 * TCP Fingerprint Firewall - eBPF packet filtering based on TCP fingerprints
 * 
 * This software is dual-licensed under:
 * - GNU Affero General Public License v3.0 (AGPLv3) - for those willing to comply with AGPLv3 terms
 * - Proprietary license - for those who cannot or do not want to adhere to AGPLv3 terms
 * 
 * If you do not want to be bound by the AGPLv3 terms (such as releasing source code
 * for modifications or network usage), you must acquire a proprietary license.
 * 
 * See the LICENSE file for details.
 */

//
// XDP Filter for TCP Fingerprint Detection
// 
// This program implements a high-performance packet filter at the XDP layer
// to detect and block packets based on TCP fingerprints in MuonFP format.
// It supports patterns like window_size:options:mss:window_scale with wildcards.
//

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stdbool.h>

#define TCP_HEADER_SIZE 20
#define XDP_PASS 2
#define XDP_DROP 1

// Field check bits
#define CHECK_WINDOW_SIZE  (1 << 0)
#define CHECK_OPTIONS      (1 << 1)
#define CHECK_MSS          (1 << 2)
#define CHECK_WINDOW_SCALE (1 << 3)

/**
 * TCP Fingerprint structure - Enhanced for MuonFP format matching with sequence support
 */
struct tcp_fingerprint {
    __u16 window_size;        // TCP window size to match
    __u16 mss;                // MSS value to match
    __u8  window_scale;       // Window scale value to match
    __u8  options_kind;       // Required options kind for simple patterns
    __u8  fields_to_check;    // Which fields to check (bitmap)
    __u8  action;             // XDP_DROP or XDP_PASS
    
    // New fields for complex options sequence matching
    __u8  options_sequence[16]; // Stores the expected option kinds in sequence (up to 16 options)
    __u8  sequence_len;         // Length of the sequence (0 if not using sequence)
    __u8  reserved[7];          // Reserved for future use (alignment padding)
    
    // Note: The options field in MuonFP can be:
    // - "*": any options are allowed (don't check options)
    // - "": no options allowed (options_kind=0, fields_to_check has CHECK_OPTIONS)
    // - "2": only option 2 (MSS) is allowed, exactly (options_kind=2, fields_to_check has CHECK_OPTIONS)
    // - "2-3-4": complex options string; this now uses the options_sequence field
} __attribute__((aligned(8)));

/**
 * Key for the multi-fingerprint map
 * Combines IP address with fingerprint ID to allow multiple fingerprints per IP
 */
struct ip_fp_key {
    __u32 ip;                // Source IP address
    __u8  fingerprint_id;    // ID of matching fingerprint (0-63)
    __u8  reserved[3];       // Padding for alignment
} __attribute__((aligned(8)));

/**
 * Blocked IPs tracking
 */
struct ip_stats {
    __u64 timestamp;         // When it was last seen
    __u64 count;             // Number of matches
    __u16 window_size;       // Window size from last packet
    __u16 mss;               // MSS from last packet (if any)
    __u8  window_scale;      // Window scale from last packet (if any)
    __u64 options_bitmap;    // Bitmap of TCP options present in the packet
} __attribute__((aligned(8)));

/**
 * Map for blocked IP addresses (legacy single-fingerprint map, still used by matching logic)
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);       // Source IP
    __type(value, struct ip_stats);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} blocked_ips SEC(".maps");

/**
 * New map for multi-fingerprint tracking
 * This allows us to track multiple fingerprints per IP address for better display
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, struct ip_fp_key);
    __type(value, struct ip_stats);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} multi_fingerprint_ips SEC(".maps");

/**
 * Map for TCP fingerprints
 * Increased to 64 fingerprints for better coverage
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);       // Fingerprint ID (0-63)
    __type(value, struct tcp_fingerprint);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tcp_fingerprints SEC(".maps");

/**
 * Configuration and stats
 */
struct config {
    __u8  fingerprint_count;  // Number of active fingerprints
    __u8  default_action;     // Default action (XDP_PASS or XDP_DROP)
    __u16 reserved;
    __u32 total_matches;      // Total number of matches
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);       // Always 0
    __type(value, struct config);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} config_map SEC(".maps");

/**
 * Parse TCP options and extract fingerprint-relevant data
 * 
 * Enhanced version that tracks option sequence for complex string matching
 */
static __always_inline bool extract_fingerprint_data(struct tcphdr *tcph, void *data_end,
                                                    __u16 *window_size, __u16 *mss, 
                                                    __u8 *window_scale, __u8 *has_options,
                                                    __u64 *options_bitmap, __u8 *option_sequence, __u8 *sequence_len) {
    // Get window size
    *window_size = bpf_ntohs(tcph->window);
    
    // Default values - explicitly initialized for verification
    *mss = 0;
    *window_scale = 0;
    *options_bitmap = 0;
    
    // Calculate TCP options length
    __u8 tcp_header_len = tcph->doff * 4;
    
    // Check if packet has TCP options
    if (tcp_header_len <= TCP_HEADER_SIZE) {
        *has_options = 0;
        return true;
    }
    
    *has_options = 1;
    
    // Base pointer to the TCP options
    __u8 *options = (__u8 *)tcph + TCP_HEADER_SIZE;
    
    // Define a maximum options length we'll process
    __u8 max_options_len = tcp_header_len - TCP_HEADER_SIZE;
    
    // Ensure we don't exceed packet boundary or reasonable size limits
    if (max_options_len > 40) // Reasonable upper limit for TCP options
        max_options_len = 40;
        
    // Check if options would exceed packet boundary
    if ((void *)(options + max_options_len) > data_end) {
        // Adjust max_options_len to fit within packet boundary
        max_options_len = data_end - (void *)options;
        
        // If no valid options can be processed, bail out
        if (max_options_len <= 0)
            return false;
    }
    
    // Initialize sequence parameters for the caller
    *sequence_len = 0;
    // Zero-initialize the option_sequence array (must be done in eBPF)
    // Support up to 16 distinct options (TCP options can be up to 40 bytes)
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        option_sequence[i] = 0;
    }
    
    // Scan options in a verifier-friendly way using fixed indices
    __u8 offset = 0;
    __u8 valid_options = 0; // Track non-NOP, non-EOL options
    
    // This method handles options more thoroughly by processing each option in sequence
    // Unrolling the loop with fixed bounds to make the verifier happy
    #pragma unroll
    for (int i = 0; i < 8; i++) {  // Process up to 8 distinct options (reasonable limit)
        // Make sure we're still within bounds
        if (offset >= max_options_len || (void *)(options + offset) >= data_end)
            break;
            
        // Read option kind
        __u8 kind = options[offset];
        
        // Track this option in our bitmap
        if (kind < 64) {
            *options_bitmap |= (1ULL << kind);
            
            // Count real options (not NOP or EOL)
            if (kind > 1)
                valid_options++;
        }
        
        // Save the option to our sequence (only real options, not padding)
        if (kind > 1 && *sequence_len < 16) {
            option_sequence[*sequence_len] = kind;
            (*sequence_len)++;
        }
        
        // Handle option types
        if (kind == 0) {
            // End of options
            break;
        } else if (kind == 1) {
            // NOP - just skip to next byte
            offset++;
        } else {
            // Options with length field
            if ((void *)(options + offset + 1) >= data_end)
                break;
                
            __u8 len = options[offset + 1];
            if (len < 2 || offset + len > max_options_len || (void *)(options + offset + len) > data_end)
                break;  // Invalid length or would exceed boundaries
            
            // Handle specific option types we care about
            if (kind == 2 && len == 4) {  // MSS
                if ((void *)(options + offset + 3) >= data_end || (void *)(options + offset + 4) >= data_end)
                    break;
                    
                *mss = (options[offset + 2] << 8) | options[offset + 3];
            } else if (kind == 3 && len == 3) {  // Window Scale
                if ((void *)(options + offset + 2) >= data_end)
                    break;
                    
                *window_scale = options[offset + 2];
            }
            
            // Move to next option
            offset += len;
        }
    }
    
    // Ensure has_options reflects if we have any actual options (excluding NOPs and EOLs)
    // This way, "::" pattern (no options) won't match a packet with only NOP and EOL
    *has_options = (valid_options > 0) ? 1 : 0;
    
    // We've now extracted:
    // 1. All options in the options_bitmap (for basic presence detection)
    // 2. The sequence of options in option_sequence array (for complex matching)
    // 3. MSS and window scale values, if present
    
    return true;
}

/**
 * Check if packet matches fingerprint
 */
static __always_inline bool match_fingerprint(struct tcp_fingerprint *fp, 
                                            __u16 window_size, __u16 mss,
                                            __u8 window_scale, __u8 has_options,
                                            __u64 options_bitmap) {
    // Check window size if required
    if ((fp->fields_to_check & CHECK_WINDOW_SIZE) && 
        fp->window_size != window_size) {
        return false;
    }
    
    // Handle options matching with different cases
    
    // Case 1: Check options presence/absence if explicitly required by rule
    if (fp->fields_to_check & CHECK_OPTIONS) {
        // If options_kind is 0, requires NO options at all
        if (fp->options_kind == 0) {
            if (has_options) {
                return false;  // Packet has options but fingerprint requires none
            }
        } 
        // If options_kind is a single number, then ONLY that option should be present
        else if (fp->options_kind < 64) {
            // Check if the specified option is present
            if ((options_bitmap & (1ULL << fp->options_kind)) == 0) {
                return false;  // Required option not present
            }
            
            // For MuonFP format ":2:", ensure there are no other options
            __u64 allowed_bitmap = (1ULL << fp->options_kind);
            
            // Check that only the allowed option bits are set - no others
            if (options_bitmap != allowed_bitmap) {
                return false;  // Other options are present or the required one is missing
            }
        }
    }
    // Case 2: Complex option sequence is defined - must match exactly
    else if (fp->sequence_len > 0) {
        // First, verify all required options are present in the bitmap
        #pragma unroll 16
        for (int i = 0; i < 16; i++) {
            // Only process valid sequence entries up to sequence_len
            if (i >= fp->sequence_len) 
                break;
            __u8 req_option = fp->options_sequence[i];
            if (req_option > 0 && req_option < 64) {
                if ((options_bitmap & (1ULL << req_option)) == 0) {
                    return false;  // Required option not present
                }
            }
        }
        
        // We still verify MSS and window_scale requirements
        if (fp->fields_to_check & CHECK_MSS) {
            // MSS requirement - option 2 must be present
            if ((options_bitmap & (1ULL << 2)) == 0) {
                return false;  // MSS required but option 2 not present
            }
            
            // If we're checking MSS value, it must match the specified value
            if (fp->mss != mss) {
                return false;  // MSS value doesn't match
            }
        }
        
        if (fp->fields_to_check & CHECK_WINDOW_SCALE) {
            // Window scale requirement - option 3 must be present
            if ((options_bitmap & (1ULL << 3)) == 0) {
                return false;  // Window scale required but option 3 not present
            }
            
            // If we're checking window scale value, it must match the specified value
            if (fp->window_scale != window_scale) {
                return false;  // Window scale value doesn't match
            }
        }
        
        return true; // Sequence matching passed all checks
    }
    // Case 3: Wildcard options (no explicit check requested) but packet does have options
    // If rule doesn't care about options (wildcard *) but still has other fields checked
    else if (has_options) {
        // The rule doesn't explicitly check options, but packet has options
        // Continue with other checks - this is the key change for "1024:*:*:*" matching "1024:2:1460:*"
    }
    
    // Check MSS if required
    if ((fp->fields_to_check & CHECK_MSS) && fp->mss != mss) {
        return false;
    }
    
    // Check window scale if required
    if ((fp->fields_to_check & CHECK_WINDOW_SCALE) && 
        fp->window_scale != window_scale) {
        return false;
    }
    
    // All checks passed
    return true;
}

/**
 * Update IP stats when a match is found
 */
static __always_inline void update_ip_stats(__u32 ip, __u16 window_size, __u16 mss,
                                           __u8 window_scale, __u8 fingerprint_id,
                                           __u64 options_bitmap) {
    __u64 timestamp = bpf_ktime_get_ns();
    
    // Create the stats structure
    struct ip_stats stats = {
        .timestamp = timestamp,
        .count = 1,
        .window_size = window_size,
        .mss = mss,
        .window_scale = window_scale,
        .options_bitmap = options_bitmap
    };
    
    // First, update the legacy map (for backward compatibility and matching logic)
    struct ip_stats *existing = bpf_map_lookup_elem(&blocked_ips, &ip);
    if (existing) {
        stats.count = existing->count + 1;
    }
    
    // Update legacy map
    bpf_map_update_elem(&blocked_ips, &ip, &stats, BPF_ANY);
    
    // Now, update the multi-fingerprint map
    struct ip_fp_key fp_key = {
        .ip = ip,
        .fingerprint_id = fingerprint_id
    };
    
    // Check if this specific fingerprint exists for this IP
    struct ip_stats *multi_existing = bpf_map_lookup_elem(&multi_fingerprint_ips, &fp_key);
    if (multi_existing) {
        // Update existing entry
        stats.count = multi_existing->count + 1;
    } else {
        // Reset count to 1 for new fingerprint entries
        // This fixes the bug where new fingerprints inherit counts
        // from the legacy map or other fingerprints
        stats.count = 1;
    }
    
    // Update multi-fingerprint map
    bpf_map_update_elem(&multi_fingerprint_ips, &fp_key, &stats, BPF_ANY);
    
    // Update total match counter
    __u32 key = 0;
    struct config *cfg = bpf_map_lookup_elem(&config_map, &key);
    if (cfg) {
        cfg->total_matches++;
    }
}

/**
 * Main XDP filter function
 */
SEC("xdp")
int xdp_scanner_filter(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // Check config first
    __u32 key = 0;
    struct config *cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!cfg || cfg->fingerprint_count == 0) {
        return XDP_PASS;
    }
    
    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Check for IPv4
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    // Parse IP header
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;
    
    // Check for TCP
    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;
        
    // For testing, we'll process all traffic including internal IPs
    // In production, you would UNCOMMENT these exemptions
    
    /*
    // Check for loopback traffic (always pass)
    if (iph->daddr == 0x0100007F || iph->saddr == 0x0100007F)  // 127.0.0.1 in network byte order
        return XDP_PASS;  // Loopback traffic, pass it
        
    // Check for common private IP ranges (outbound traffic)
    // Using consistent network byte order handling with correct masks
    __u32 saddr = iph->saddr;  // Network byte order (big endian)
    __u8 first_octet = (__u8)(saddr & 0xFF);  // First octet in host byte order
    __u8 second_octet = (__u8)((saddr >> 8) & 0xFF);  // Second octet in host byte order

    // 10.0.0.0/8 (Class A private) - first octet is 10
    if (first_octet == 10)
        return XDP_PASS;
    
    // 172.16.0.0/12 (Class B private): 172.16.0.0 to 172.31.255.255
    if (first_octet == 172 && (second_octet >= 16 && second_octet <= 31))
        return XDP_PASS;
    
    // 192.168.0.0/16 (Class C private) - 192.168.x.x
    if (first_octet == 192 && second_octet == 168)
        return XDP_PASS;
    
    // 169.254.0.0/16 (Link local) - 169.254.x.x
    if (first_octet == 169 && second_octet == 254)
        return XDP_PASS;
    */
    
    // Parse TCP header (after IP header)
    __u8 ihl = iph->ihl * 4;
    
    // Ensure bounds check is verifier-friendly - use explicit pointer arithmetic
    struct tcphdr *tcph = (void *)iph + ihl;
    if ((void *)(tcph + 1) > data_end)
        return XDP_PASS;
    
    // Only process SYN packets without ACK (initial connection attempts)
    if (!(tcph->syn && !tcph->ack))
        return XDP_PASS;

    // Optional debug: update the reserved field in the config map
    // with the current window size - useful for debugging
    if (cfg && cfg->fingerprint_count > 0) {
        cfg->reserved = bpf_ntohs(tcph->window);
    }
    
    // Extract fingerprint data
    __u16 window_size;
    __u16 mss = 0;
    __u8 window_scale = 0;
    __u8 has_options = 0;
    __u64 options_bitmap = 0;
    // New array to capture TCP option sequence
    __u8 option_sequence[16] = {0};
    __u8 sequence_len = 0;
    
    if (!extract_fingerprint_data(tcph, data_end, &window_size, &mss, 
                                 &window_scale, &has_options, &options_bitmap,
                                 option_sequence, &sequence_len)) {
        return XDP_PASS;  // Option parsing error
    }
    
    // Check against fingerprints (up to 64 fingerprints)
    for (int i = 0; i < 64 && i < cfg->fingerprint_count; i++) {
        __u32 fp_idx = i;
        struct tcp_fingerprint *fp = bpf_map_lookup_elem(&tcp_fingerprints, &fp_idx);
        if (!fp) {
            continue;
        }
        
        if (match_fingerprint(fp, window_size, mss, window_scale, has_options, options_bitmap)) {
            // Match found - update statistics and return action
            // We should also store the options_sequence, but our current stats structure doesn't have 
            // a dedicated field for this. For now, we'll just store the bitmap.
            update_ip_stats(iph->saddr, window_size, mss, window_scale, fp_idx, options_bitmap);
            return fp->action;
        }
    }
    
    // No match - use default action
    return cfg->default_action;
}

char LICENSE[] SEC("license") = "Dual AGPL/Proprietary";