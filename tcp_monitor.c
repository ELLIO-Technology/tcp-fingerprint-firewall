/**
 * TCP Fingerprint Monitor
 * htop-like visualization tool for real-time TCP fingerprint monitoring
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <ctype.h>
#include <sys/ioctl.h>
#include <ncurses.h>

// Define constants
#define MAP_PATH_BASE "/sys/fs/bpf"
#define XDP_PASS 2
#define XDP_DROP 1

// Field check bits (must match eBPF program)
#define CHECK_WINDOW_SIZE  (1 << 0)
#define CHECK_OPTIONS      (1 << 1)
#define CHECK_MSS          (1 << 2)
#define CHECK_WINDOW_SCALE (1 << 3)

// Define max entries
#define MAX_ENTRIES 1000
#define MAX_DISPLAY_ENTRIES 100

// Log file path for mismatch detection - can be changed at compile time with -DLOG_FILE_PATH=\"/path/to/log\"
#ifndef LOG_FILE_PATH
#define LOG_FILE_PATH "/tmp/tcp_fingerprint_mismatches.log"
#endif

// Color pair definitions
#define COLOR_NORMAL       1
#define COLOR_HIGHLIGHT    2
#define COLOR_IP           3
#define COLOR_WINDOW_SIZE  4
#define COLOR_OPTIONS      5
#define COLOR_MSS          6
#define COLOR_SCALE        7
#define COLOR_DROP         8
#define COLOR_PASS         9
#define COLOR_HEADER       10
#define COLOR_SORT         11
#define COLOR_BAR          12

// Global control flags
static volatile bool running = true;
static int debug = 0;

// Display settings
typedef struct {
    bool show_drop;
    bool show_pass;
    char filter[64];
    int sort_by;        // 0=time, 1=hits, 2=ip
    bool reverse_sort;
    int selected_row;
    bool show_details;
    int start_row;
    bool paused;        // Pause auto-refresh for copying text
} display_settings_t;

// Sort constants
enum {
    SORT_BY_TIME = 0,
    SORT_BY_HITS = 1,
    SORT_BY_IP = 2,
    SORT_BY_MUONFP = 3
};

/**
 * TCP Fingerprint structure (must match eBPF program)
 */
struct tcp_fingerprint {
    uint16_t window_size;        // TCP window size to match
    uint16_t mss;                // MSS value to match
    uint8_t  window_scale;       // Window scale value to match
    uint8_t  options_kind;       // Required options kind (0=none, 1=noop, 2=mss, 3=wscale)
    uint8_t  fields_to_check;    // Which fields to check (bitmap)
    uint8_t  action;             // XDP_DROP or XDP_PASS
    
    // New fields for option sequence matching
    uint8_t  options_sequence[16]; // Stores the expected option kinds in sequence (up to 16 options)
    uint8_t  sequence_len;         // Length of the sequence (0 if not using sequence)
    uint8_t  reserved[7];          // Reserved for future use (alignment padding)
};

/**
 * Composite key structure for multi-fingerprint tracking
 */
struct ip_fp_key {
    uint32_t ip;                // Source IP address
    uint8_t  fingerprint_id;    // ID of matching fingerprint (0-63)
    uint8_t  reserved[3];       // Padding for alignment
};

/**
 * Stats structure (must match eBPF program)
 */
struct ip_stats {
    uint64_t timestamp;         // When it was last seen
    uint64_t count;             // Number of matches
    uint16_t window_size;       // Window size from last packet
    uint16_t mss;               // MSS from last packet (if any)
    uint8_t  window_scale;      // Window scale from last packet (if any)
    uint64_t options_bitmap;    // Bitmap of TCP options present in the packet
};

/**
 * Config structure (must match eBPF program)
 */
struct config {
    uint8_t  fingerprint_count;  // Number of active fingerprints
    uint8_t  default_action;     // Default action (XDP_PASS or XDP_DROP)
    uint16_t reserved;
    uint32_t total_matches;      // Total number of matches
};

// Collected fingerprint data for display
typedef struct {
    struct ip_stats stats;
    uint8_t fingerprint_id;
    uint32_t ip;
    char ip_str[INET_ADDRSTRLEN];
    char packet_fp[64];
    char rule_str[64];
    uint8_t action;
    time_t actual_time;
    uint64_t prev_count;  // For calculating rate
    double rate;          // Hits per second
} fingerprint_entry_t;

/**
 * Initialize a fingerprint entry with safe defaults
 */
static void init_fingerprint_entry(fingerprint_entry_t *entry) {
    if (entry) {
        memset(entry, 0, sizeof(*entry));
        entry->ip_str[0] = '\0';
        strncpy(entry->packet_fp, "Unknown", sizeof(entry->packet_fp)-1);
        entry->packet_fp[sizeof(entry->packet_fp)-1] = '\0';
        strncpy(entry->rule_str, "Unknown", sizeof(entry->rule_str)-1);
        entry->rule_str[sizeof(entry->rule_str)-1] = '\0';
        entry->action = XDP_PASS;
        entry->actual_time = time(NULL);
        entry->prev_count = 0;
        entry->rate = 0.0;
    }
}

// Summary statistics
typedef struct {
    int total_fingerprints;
    int drop_fingerprints;
    int pass_fingerprints;
    uint64_t total_hits;
    uint64_t drop_hits;
    uint64_t pass_hits;
    double total_rate;
    double drop_rate;
    double pass_rate;
    int active_ips;
} stats_summary_t;

// Terminal state
typedef struct {
    int rows;
    int cols;
} terminal_size_t;

/**
 * Signal handler for clean termination
 */
static void signal_handler(int signo)
{
    (void)signo;  // Unused parameter, silence warning
    running = false;
}

/**
 * Convert action (XDP_PASS/XDP_DROP) to string
 */
static const char* action_to_string(uint8_t action)
{
    if (action == XDP_DROP)
        return "DROP";
    else
        return "PASS";
}

/**
 * Format options bitmap into a hyphen-separated string
 */
static void format_options_bitmap(uint64_t bitmap, char *buf, size_t bufsize)
{
    if (bitmap > 0) {
        int pos = 0;
        bool has_options = false;
        
        for (int opt = 1; opt < 32; opt++) {  // Skip option 0 (end of options)
            if (bitmap & (1ULL << opt)) {
                if (has_options) {
                    pos += snprintf(buf + pos, bufsize - pos, "-");
                }
                pos += snprintf(buf + pos, bufsize - pos, "%d", opt);
                has_options = true;
                
                if ((size_t)pos >= bufsize - 1) {
                    break;  // Avoid buffer overflow
                }
            }
        }
    } else {
        buf[0] = '\0';  // Empty string if no options
    }
}

/**
 * Format a TCP fingerprint in MuonFP format
 */
static void format_muonfp(const struct tcp_fingerprint *fp, char *buf, size_t bufsize)
{
    // Build the MuonFP string in window_size:options:mss:window_scale format
    
    // Window size
    char window_str[16] = "*";
    if (fp->fields_to_check & CHECK_WINDOW_SIZE) {
        snprintf(window_str, sizeof(window_str), "%u", fp->window_size);
    }
    
    // Options
    char option_str[64] = "*";
    if (fp->sequence_len > 0) {
        // Complex option sequence
        option_str[0] = '\0';
        int pos = 0;
        for (int i = 0; i < fp->sequence_len; i++) {
            if (i > 0) {
                pos += snprintf(option_str + pos, sizeof(option_str) - pos, "-");
            }
            pos += snprintf(option_str + pos, sizeof(option_str) - pos, "%d", fp->options_sequence[i]);
        }
    } else if (fp->fields_to_check & CHECK_OPTIONS) {
        if (fp->options_kind == 0) {
            option_str[0] = '\0'; // Empty string for no options
        } else if (fp->options_kind == 255) {
            // This should not happen in most cases, but for clarity
            snprintf(option_str, sizeof(option_str), "complex");
        } else {
            snprintf(option_str, sizeof(option_str), "%d", fp->options_kind);
        }
    }
    
    // MSS
    char mss_str[16] = "*";
    if (fp->fields_to_check & CHECK_MSS) {
        if (fp->mss == 0) {
            mss_str[0] = '\0'; // Empty string for no MSS
        } else {
            snprintf(mss_str, sizeof(mss_str), "%u", fp->mss);
        }
    }
    
    // Window scale
    char wscale_str[16] = "*";
    if (fp->fields_to_check & CHECK_WINDOW_SCALE) {
        if (fp->window_scale == 0) {
            wscale_str[0] = '\0'; // Empty string for no window scale
        } else {
            snprintf(wscale_str, sizeof(wscale_str), "%u", fp->window_scale);
        }
    }
    
    // Format the complete MuonFP string
    snprintf(buf, bufsize, "%s:%s:%s:%s", window_str, option_str, mss_str, wscale_str);
}

/**
 * Format matched rule and retrieve the associated fingerprint structure
 */
static bool format_matched_rule(int fp_map, uint8_t fp_id, char *rule_buf, struct tcp_fingerprint *result_fp)
{
    // Initialize to a safe value
    if (rule_buf) {
        strncpy(rule_buf, "Unknown", 64);
        rule_buf[63] = '\0'; // Ensure null termination
    }
    bool success = false;
    
    // Check if the fingerprint ID is valid
    // We use a larger max (64) to support both simple filter (10) and full filter (64)
    if (fp_id < 64) {
        uint32_t fp_key = fp_id;
        struct tcp_fingerprint fp;
        
        // Try to lookup the fingerprint in the map
        if (bpf_map_lookup_elem(fp_map, &fp_key, &fp) == 0) {
            // Format the fingerprint into MuonFP format
            if (rule_buf) {
                format_muonfp(&fp, rule_buf, 64);
            }
            
            // Copy the fingerprint structure if requested
            if (result_fp) {
                *result_fp = fp;
                success = true;
            } else {
                success = true; // Still successful even if result_fp is NULL
            }
        }
    }
    
    return success;
}

/**
 * Format a packet's TCP fingerprint into MuonFP format
 */
static void format_packet_fingerprint(const struct ip_stats *stats, uint8_t fingerprint_id, char *buf, size_t bufsize)
{
    // Look up the matching rule to use its format
    uint8_t fp_id = fingerprint_id;
    struct tcp_fingerprint matched_fp;
    bool got_rule = false;
    
    // Get the fingerprint rule that matched this packet
    int fp_map = bpf_obj_get("/sys/fs/bpf/tcp_fingerprints");
    if (fp_map >= 0 && fp_id < 64) {
        uint32_t fp_key = fp_id;
        if (bpf_map_lookup_elem(fp_map, &fp_key, &matched_fp) == 0) {
            got_rule = true;
        }
        close(fp_map);
    }
    
    // Format options field of the packet fingerprint
    char options_str[32] = "";
    
    // If we got the matched rule, use its options format
    if (got_rule) {
        // Use options from the matched rule
        if (matched_fp.sequence_len > 0) {
            // Use the same sequence as the rule
            int pos = 0;
            for (int i = 0; i < matched_fp.sequence_len; i++) {
                if (i > 0) {
                    pos += snprintf(options_str + pos, sizeof(options_str) - pos, "-");
                }
                pos += snprintf(options_str + pos, sizeof(options_str) - pos, "%d", matched_fp.options_sequence[i]);
            }
        } else if (matched_fp.fields_to_check & CHECK_OPTIONS) {
            // Single option number
            if (matched_fp.options_kind == 0) {
                options_str[0] = '\0';  // No options
            } else {
                snprintf(options_str, sizeof(options_str), "%d", matched_fp.options_kind);
            }
        } else {
            // Default to showing actual bitmap
            format_options_bitmap(stats->options_bitmap, options_str, sizeof(options_str));
        }
    } else {
        // Default to showing actual bitmap
        format_options_bitmap(stats->options_bitmap, options_str, sizeof(options_str));
    }
    
    // MSS and window scale values
    char mss_str[16] = "";
    char wscale_str[16] = "";
    
    // If we have the rule, format according to the rule
    if (got_rule) {
        // MSS formatting
        if (matched_fp.fields_to_check & CHECK_MSS) {
            if (matched_fp.mss == 0) {
                // Empty string (no MSS)
                mss_str[0] = '\0';
            } else if (stats->options_bitmap & (1ULL << 2)) {
                // Show actual MSS if present
                snprintf(mss_str, sizeof(mss_str), "%u", stats->mss);
            } else {
                // Use rule MSS if packet doesn't have it
                snprintf(mss_str, sizeof(mss_str), "%u", matched_fp.mss);
            }
        } else if (stats->options_bitmap & (1ULL << 2)) {
            // No rule constraint, show actual MSS if present
            snprintf(mss_str, sizeof(mss_str), "%u", stats->mss);
        }
        
        // Window scale formatting
        if (matched_fp.fields_to_check & CHECK_WINDOW_SCALE) {
            if (matched_fp.window_scale == 0) {
                // Empty string (no window scale)
                wscale_str[0] = '\0';
            } else if (stats->options_bitmap & (1ULL << 3)) {
                // Show actual window scale if present
                snprintf(wscale_str, sizeof(wscale_str), "%u", stats->window_scale);
            } else {
                // Use rule window scale if packet doesn't have it
                snprintf(wscale_str, sizeof(wscale_str), "%u", matched_fp.window_scale);
            }
        } else if (stats->options_bitmap & (1ULL << 3)) {
            // No rule constraint, show actual window scale if present
            snprintf(wscale_str, sizeof(wscale_str), "%u", stats->window_scale);
        }
    } else {
        // No rule, format based on packet content
        if (stats->options_bitmap & (1ULL << 2)) {
            snprintf(mss_str, sizeof(mss_str), "%u", stats->mss);
        }
        if (stats->options_bitmap & (1ULL << 3)) {
            snprintf(wscale_str, sizeof(wscale_str), "%u", stats->window_scale);
        }
    }
    
    // Format without colors
    snprintf(buf, bufsize, "%u:%s:%s:%s", 
            stats->window_size,
            options_str,
            mss_str,
            wscale_str);
}

/**
 * Collect all fingerprint data from the maps
 * Returns the number of entries collected
 */
static int collect_fingerprint_data(fingerprint_entry_t *entries, int max_entries)
{
    int count = 0;
    
    // Open maps
    int ip_map = bpf_obj_get("/sys/fs/bpf/blocked_ips");
    int fp_map = bpf_obj_get("/sys/fs/bpf/tcp_fingerprints");
    
    if (ip_map < 0 || fp_map < 0) {
        if (debug) {
            mvprintw(0, 0, "Failed to access maps. Is the firewall loaded?");
            refresh();
        }
        return 0;
    }
    
    // Try to open multi-fingerprint map
    char multi_fingerprint_path[256];
    snprintf(multi_fingerprint_path, sizeof(multi_fingerprint_path), "%s/multi_fingerprint_ips", 
             "/sys/fs/bpf");
    int multi_fp_map = bpf_obj_get(multi_fingerprint_path);
    bool using_multi_map = (multi_fp_map >= 0);
    
    // Get current time for timestamp calculations
    time_t current_time = time(NULL);
    time_t uptime_secs = 0;
    
    // Get system uptime from /proc/uptime - use double for better precision
    FILE *uptime_file = fopen("/proc/uptime", "r");
    if (uptime_file) {
        double uptime;
        if (fscanf(uptime_file, "%lf", &uptime) == 1) {
            uptime_secs = (time_t)uptime;
        }
        fclose(uptime_file);
    }
    
    // Calculate boot time once to avoid jitter
    time_t boot_time = current_time - uptime_secs;
    
    // Save current count to calculate rates
    for (int i = 0; i < max_entries && i < count; i++) {
        entries[i].prev_count = entries[i].stats.count;
    }
    
    // Reset count to refill the array
    count = 0;
    
    // Initialize all entries with safe defaults
    for (int i = 0; i < max_entries; i++) {
        init_fingerprint_entry(&entries[i]);
    }
    
    // Read from multi-fingerprint map if available
    if (using_multi_map) {
        struct ip_fp_key key, next_key;
        memset(&key, 0, sizeof(key));
        
        while (bpf_map_get_next_key(multi_fp_map, &key, &next_key) == 0 && count < max_entries) {
            struct ip_stats stats;
            
            if (bpf_map_lookup_elem(multi_fp_map, &next_key, &stats) == 0) {
                // Fill in the entry
                fingerprint_entry_t *entry = &entries[count];
                
                // Store previous count to calculate rate - need to find the exact entry
                uint64_t prev_count = 0;
                bool found_existing = false;
                
                // Check if this is an existing entry that we're updating (exact match on IP and fingerprint ID)
                for (int i = 0; i < max_entries; i++) {
                    if (entries[i].ip == next_key.ip && 
                        entries[i].fingerprint_id == next_key.fingerprint_id) {
                        prev_count = entries[i].stats.count; // Use the current count, not prev_count
                        found_existing = true;
                        break;
                    }
                }
                
                entry->stats = stats;
                entry->fingerprint_id = next_key.fingerprint_id;
                entry->ip = next_key.ip;
                
                // For brand new entries, initialize prev_count to current count 
                // This prevents new entries from showing artificially high rates
                if (!found_existing) {
                    prev_count = stats.count;
                }
                
                entry->prev_count = prev_count; // Store last count we saw
                
                // Convert IP to string
                struct in_addr addr = { .s_addr = entry->ip };
                inet_ntop(AF_INET, &addr, entry->ip_str, sizeof(entry->ip_str));
                
                // Format fingerprint string - this is the actual packet fingerprint 
                // that was detected, NOT what rule matched it
                format_packet_fingerprint(&stats, entry->fingerprint_id, entry->packet_fp, sizeof(entry->packet_fp));
                
                // Get rule info - this is the filter rule that matched the packet
                struct tcp_fingerprint matched_fp;
                if (format_matched_rule(fp_map, entry->fingerprint_id, entry->rule_str, &matched_fp)) {
                    entry->action = matched_fp.action;
                } else {
                    entry->action = XDP_PASS; // Default
                    // Ensure we have a valid string in rule_str
                    strncpy(entry->rule_str, "Unknown", sizeof(entry->rule_str)-1);
                    entry->rule_str[sizeof(entry->rule_str)-1] = '\0';
                }
                
                // Check for mismatch between detected fingerprint and matching rule
                // This could indicate a problem in the fingerprint matching logic
                if (strcmp(entry->packet_fp, entry->rule_str) != 0) {
                    // Always record the mismatch in a log file for later analysis
                    FILE *log_file = fopen(LOG_FILE_PATH, "a");
                    if (log_file) {
                        time_t now = time(NULL);
                        char time_buf[64];
                        struct tm *tm_info = localtime(&now);
                        strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);
                        
                        // Safe, bounded logging
                        fprintf(log_file, "[%s] Mismatch: IP=%s, ID=%d, Fingerprint=\"%s\", Rule=\"%s\"\n",
                                time_buf, entry->ip_str, entry->fingerprint_id,
                                entry->packet_fp, entry->rule_str);
                        fclose(log_file);
                    }
                    
                    // Only display on screen in debug mode
                    if (debug) {
                        char safe_message[256];
                        snprintf(safe_message, sizeof(safe_message), 
                                "Mismatch: FP='%.30s' Rule='%.30s'",
                                entry->packet_fp, entry->rule_str);
                        mvprintw(0, 0, "%-80s", safe_message);  // Pad with spaces to clear previous messages
                        refresh();
                    }
                }
                
                // Calculate actual time using pre-calculated boot_time to avoid jitter
                time_t timestamp_secs = stats.timestamp / 1000000000ULL;
                entry->actual_time = boot_time + timestamp_secs;
                
                // Calculate hits per second - better rate handling
                if (found_existing && prev_count > 0 && entry->stats.count >= prev_count) {
                    // We know the previous count, calculate rate properly
                    entry->rate = (double)(entry->stats.count - prev_count);
                    
                    // Limit to reasonable values to avoid display issues
                    if (entry->rate > 999999.0) {
                        entry->rate = 999999.0;
                    }
                } else {
                    // New entry or reset counter
                    entry->rate = 0.0;
                }
                
                count++;
            }
            
            key = next_key;
        }
    }
    
    // If multi-map is not available or empty, fall back to legacy map
    if (count == 0 && ip_map >= 0) {
        uint32_t key = 0, next_key;
        
        while (bpf_map_get_next_key(ip_map, &key, &next_key) == 0 && count < max_entries) {
            struct ip_stats stats;
            
            if (bpf_map_lookup_elem(ip_map, &next_key, &stats) == 0) {
                // Fill in the entry
                fingerprint_entry_t *entry = &entries[count];
                
                // Store previous count to calculate rate - need to find the exact entry
                uint64_t prev_count = 0;
                bool found_existing = false;
                
                // Check if this is an existing entry that we're updating (match by IP for legacy map)
                for (int i = 0; i < max_entries; i++) {
                    if (entries[i].ip == next_key) {
                        prev_count = entries[i].stats.count; // Use the current count, not prev_count
                        found_existing = true;
                        break;
                    }
                }
                
                entry->stats = stats;
                entry->fingerprint_id = 0;  // Default for legacy map
                entry->ip = next_key;
                
                // For brand new entries, initialize prev_count to current count
                // This prevents new entries from showing artificially high rates
                if (!found_existing) {
                    prev_count = stats.count;
                }
                
                entry->prev_count = prev_count; // Store last count we saw
                
                // Convert IP to string
                struct in_addr addr = { .s_addr = entry->ip };
                inet_ntop(AF_INET, &addr, entry->ip_str, sizeof(entry->ip_str));
                
                // Format fingerprint string
                format_packet_fingerprint(&stats, entry->fingerprint_id, entry->packet_fp, sizeof(entry->packet_fp));
                
                // Get rule info and action
                struct tcp_fingerprint matched_fp;
                if (format_matched_rule(fp_map, entry->fingerprint_id, entry->rule_str, &matched_fp)) {
                    entry->action = matched_fp.action;
                } else {
                    entry->action = XDP_PASS; // Default
                    // Ensure we have a valid string in rule_str
                    strncpy(entry->rule_str, "Unknown", sizeof(entry->rule_str)-1);
                    entry->rule_str[sizeof(entry->rule_str)-1] = '\0';
                }
                
                // Calculate actual time using pre-calculated boot_time to avoid jitter
                time_t timestamp_secs = stats.timestamp / 1000000000ULL;
                entry->actual_time = boot_time + timestamp_secs;
                
                // Calculate hits per second - better rate handling
                if (found_existing && prev_count > 0 && entry->stats.count >= prev_count) {
                    // We know the previous count, calculate rate properly
                    entry->rate = (double)(entry->stats.count - prev_count);
                    
                    // Limit to reasonable values to avoid display issues
                    if (entry->rate > 999999.0) {
                        entry->rate = 999999.0;
                    }
                } else {
                    // New entry or reset counter
                    entry->rate = 0.0;
                }
                
                count++;
            }
            
            key = next_key;
        }
    }
    
    // Close maps
    if (ip_map >= 0) close(ip_map);
    if (fp_map >= 0) close(fp_map);
    if (using_multi_map) close(multi_fp_map);
    
    return count;
}

/**
 * Compare functions for sorting
 */
static int compare_by_time(const void *a, const void *b) {
    const fingerprint_entry_t *ea = (const fingerprint_entry_t *)a;
    const fingerprint_entry_t *eb = (const fingerprint_entry_t *)b;
    
    if (ea->actual_time > eb->actual_time) return -1;
    if (ea->actual_time < eb->actual_time) return 1;
    return 0;
}

static int compare_by_hits(const void *a, const void *b) {
    const fingerprint_entry_t *ea = (const fingerprint_entry_t *)a;
    const fingerprint_entry_t *eb = (const fingerprint_entry_t *)b;
    
    if (ea->stats.count > eb->stats.count) return -1;
    if (ea->stats.count < eb->stats.count) return 1;
    return 0;
}

static int compare_by_ip(const void *a, const void *b) {
    const fingerprint_entry_t *ea = (const fingerprint_entry_t *)a;
    const fingerprint_entry_t *eb = (const fingerprint_entry_t *)b;
    
    if (ea->ip < eb->ip) return -1;
    if (ea->ip > eb->ip) return 1;
    return 0;
}

static int compare_by_muonfp(const void *a, const void *b) {
    const fingerprint_entry_t *ea = (const fingerprint_entry_t *)a;
    const fingerprint_entry_t *eb = (const fingerprint_entry_t *)b;
    
    // Compare packet fingerprints lexicographically
    return strcmp(ea->packet_fp, eb->packet_fp);
}

// Function is defined but currently not used
static int __attribute__((unused)) compare_by_rate(const void *a, const void *b) {
    const fingerprint_entry_t *ea = (const fingerprint_entry_t *)a;
    const fingerprint_entry_t *eb = (const fingerprint_entry_t *)b;
    
    if (ea->rate > eb->rate) return -1;
    if (ea->rate < eb->rate) return 1;
    return 0;
}

/**
 * Filter and sort fingerprint entries
 */
static int process_entries(fingerprint_entry_t *entries, int count, display_settings_t *settings)
{
    if (count == 0) {
        return 0;
    }
    
    // Filter by action
    if (!settings->show_drop || !settings->show_pass) {
        int filtered_count = 0;
        
        for (int i = 0; i < count; i++) {
            bool keep = (entries[i].action == XDP_DROP && settings->show_drop) ||
                       (entries[i].action == XDP_PASS && settings->show_pass);
                       
            // Also check the filter string
            if (settings->filter[0] != '\0') {
                bool match = strstr(entries[i].ip_str, settings->filter) != NULL ||
                           strstr(entries[i].packet_fp, settings->filter) != NULL ||
                           strstr(entries[i].rule_str, settings->filter) != NULL;
                
                keep = keep && match;
            }
            
            if (keep) {
                if (filtered_count != i) {
                    // Move this entry to the filtered position
                    entries[filtered_count] = entries[i];
                }
                filtered_count++;
            }
        }
        
        count = filtered_count;
    } else if (settings->filter[0] != '\0') {
        // Filter just by the filter string
        int filtered_count = 0;
        
        for (int i = 0; i < count; i++) {
            bool match = strstr(entries[i].ip_str, settings->filter) != NULL ||
                       strstr(entries[i].packet_fp, settings->filter) != NULL ||
                       strstr(entries[i].rule_str, settings->filter) != NULL;
            
            if (match) {
                if (filtered_count != i) {
                    // Move this entry to the filtered position
                    entries[filtered_count] = entries[i];
                }
                filtered_count++;
            }
        }
        
        count = filtered_count;
    }
    
    // Sort entries
    if (count > 0) {
        switch (settings->sort_by) {
            case SORT_BY_TIME:
                qsort(entries, count, sizeof(fingerprint_entry_t), compare_by_time);
                break;
            case SORT_BY_HITS:
                qsort(entries, count, sizeof(fingerprint_entry_t), compare_by_hits);
                break;
            case SORT_BY_IP:
                qsort(entries, count, sizeof(fingerprint_entry_t), compare_by_ip);
                break;
            case SORT_BY_MUONFP:
                qsort(entries, count, sizeof(fingerprint_entry_t), compare_by_muonfp);
                break;
        }
        
        // Reverse if needed
        if (settings->reverse_sort) {
            for (int i = 0; i < count / 2; i++) {
                fingerprint_entry_t temp = entries[i];
                entries[i] = entries[count - i - 1];
                entries[count - i - 1] = temp;
            }
        }
    }
    
    return count;
}

/**
 * Calculate summary statistics
 */
static void calculate_summary(fingerprint_entry_t *entries, int count, stats_summary_t *summary)
{
    memset(summary, 0, sizeof(stats_summary_t));
    
    if (count == 0) {
        return;
    }
    
    // Track unique IPs and fingerprint patterns
    uint32_t unique_ips[MAX_ENTRIES];
    char unique_patterns[MAX_ENTRIES][64];
    int unique_count = 0;
    int unique_fp_count = 0;
    
    for (int i = 0; i < count; i++) {
        // Count by action
        if (entries[i].action == XDP_DROP) {
            summary->drop_hits += entries[i].stats.count;
            summary->drop_rate += entries[i].rate;
        } else {
            summary->pass_hits += entries[i].stats.count;
            summary->pass_rate += entries[i].rate;
        }
        
        // Track unique IPs
        bool found_ip = false;
        for (int j = 0; j < unique_count; j++) {
            if (unique_ips[j] == entries[i].ip) {
                found_ip = true;
                break;
            }
        }
        
        if (!found_ip && unique_count < MAX_ENTRIES) {
            unique_ips[unique_count++] = entries[i].ip;
        }
        
        // Track unique fingerprint patterns
        bool found_pattern = false;
        for (int j = 0; j < unique_fp_count; j++) {
            if (strcmp(unique_patterns[j], entries[i].rule_str) == 0) {
                found_pattern = true;
                break;
            }
        }
        
        if (!found_pattern && unique_fp_count < MAX_ENTRIES) {
            strncpy(unique_patterns[unique_fp_count], entries[i].rule_str, sizeof(unique_patterns[0]) - 1);
            unique_patterns[unique_fp_count][sizeof(unique_patterns[0]) - 1] = '\0';
            unique_fp_count++;
            
            // Count by action for unique fingerprints
            if (entries[i].action == XDP_DROP) {
                summary->drop_fingerprints++;
            } else {
                summary->pass_fingerprints++;
            }
        }
    }
    
    // Set totals
    summary->total_fingerprints = summary->drop_fingerprints + summary->pass_fingerprints;
    summary->total_hits = summary->drop_hits + summary->pass_hits;
    summary->total_rate = summary->drop_rate + summary->pass_rate;
    summary->active_ips = unique_count;
}

/**
 * Draw a horizontal bar graph
 */
static void draw_bar(int y, int x, int width, double value, double max, int attr)
{
    int bar_width = 0;
    
    // Always draw empty bar for zero values
    // Otherwise calculate the bar width proportional to max
    if (value > 0 && max > 0) {
        double ratio = value / max;
        // Cap ratio at 1.0 to avoid overfilling
        if (ratio > 1.0) ratio = 1.0;
        bar_width = (int)(ratio * width);
        
        // Always show at least 1 character if there's any value at all
        if (bar_width == 0 && value > 0)
            bar_width = 1;
    }
    
    // Draw the bar container
    mvaddch(y, x, '[');
    
    // Draw the filled part with the specified attribute
    attron(attr);
    for (int i = 0; i < bar_width; i++) {
        mvaddch(y, x + 1 + i, '#');
    }
    attroff(attr);
    
    // Fill the rest with spaces
    for (int i = bar_width; i < width; i++) {
        mvaddch(y, x + 1 + i, ' ');
    }
    
    // Close the bar
    mvaddch(y, x + width + 1, ']');
}

/**
 * Format a number with unit prefix (K, M, G)
 */
static void format_number(uint64_t number, char *buf, size_t bufsize)
{
    if (number < 1000) {
        snprintf(buf, bufsize, "%lu", number);
    } else if (number < 1000000) {
        snprintf(buf, bufsize, "%.1fK", number / 1000.0);
    } else if (number < 1000000000) {
        snprintf(buf, bufsize, "%.1fM", number / 1000000.0);
    } else {
        snprintf(buf, bufsize, "%.1fG", number / 1000000000.0);
    }
}

/**
 * Format a time string for display
 */
static void format_time(time_t t, char *buf, size_t bufsize)
{
    struct tm *tm = localtime(&t);
    if (tm) {
        strftime(buf, bufsize, "%m-%d %H:%M:%S", tm);
    } else {
        snprintf(buf, bufsize, "Unknown");
    }
}

/**
 * Draw the header
 */
static void draw_header(const char *interface, display_settings_t *settings, int term_cols)
{
    attron(COLOR_PAIR(COLOR_HEADER) | A_BOLD);
    mvprintw(0, 0, "Recon Shield Monitor");
    attroff(COLOR_PAIR(COLOR_HEADER) | A_BOLD);
    
    mvprintw(0, 22, "| Interface: %s", interface);
    
    // Draw sort indicator on the right
    const char *sort_string;
    switch (settings->sort_by) {
        case SORT_BY_TIME:
            sort_string = "Time";
            break;
        case SORT_BY_HITS:
            sort_string = "Hits";
            break;
        case SORT_BY_IP:
            sort_string = "IP";
            break;
        case SORT_BY_MUONFP:
            sort_string = "MuonFP";
            break;
        default:
            sort_string = "?";
    }
    
    char sort_buf[32];
    snprintf(sort_buf, sizeof(sort_buf), "Sort: %s %s", 
             sort_string, 
             settings->reverse_sort ? "v" : "^"); // Use ASCII instead of Unicode arrows
             
    attron(COLOR_PAIR(COLOR_SORT));
    mvprintw(0, term_cols - strlen(sort_buf) - 2, "%s", sort_buf);
    attroff(COLOR_PAIR(COLOR_SORT));
    
    // Draw filter indicator
    if (settings->filter[0] != '\0') {
        mvprintw(0, term_cols / 2 - 5, "| Filter: %s", settings->filter);
    }
    
    // Draw pause indicator
    if (settings->paused) {
        attron(COLOR_PAIR(COLOR_DROP) | A_BOLD);  // Red and bold for visibility
        mvprintw(0, term_cols / 2 + 10, "| PAUSED");
        attroff(COLOR_PAIR(COLOR_DROP) | A_BOLD);
    }
}

/**
 * Draw summary stats
 */
static void draw_summary(stats_summary_t *summary, int term_cols, int color_pair)
{
    int y = 2;
    
    // Format numbers
    char total_hits[32], drop_hits[32], pass_hits[32];
    format_number(summary->total_hits, total_hits, sizeof(total_hits));
    format_number(summary->drop_hits, drop_hits, sizeof(drop_hits));
    format_number(summary->pass_hits, pass_hits, sizeof(pass_hits));
    
    // Determine max values for bars
    double max_rate = summary->total_rate > 0 ? summary->total_rate : 1.0;
    double max_count = summary->total_fingerprints > 0 ? summary->total_fingerprints : 1.0;
    (void)max_rate;  // May be unused in some configurations, silence warning
    
    // Don't need to modify the summary data structure here
    // The draw_bar function will handle zero values correctly
    
    // Row 1 - Active fingerprints and IPs
    attron(COLOR_PAIR(color_pair) | A_BOLD);
    mvprintw(y, 0, "Fingerprints: %d   Unique IPs: %d", 
             summary->total_fingerprints, summary->active_ips);
    attroff(COLOR_PAIR(color_pair) | A_BOLD);
    
    y++;
    
    // Format rate strings for each section
    char total_rate_str[32], drop_rate_str[32], pass_rate_str[32];
    
    // Format total rate
    if (summary->total_rate < 0.1) {
        snprintf(total_rate_str, sizeof(total_rate_str), "0 hits/sec");
    } else if (summary->total_rate < 1000) {
        snprintf(total_rate_str, sizeof(total_rate_str), "%.1f hits/sec", summary->total_rate);
    } else if (summary->total_rate < 1000000) {
        snprintf(total_rate_str, sizeof(total_rate_str), "%.1fK hits/sec", summary->total_rate/1000.0);
    } else {
        snprintf(total_rate_str, sizeof(total_rate_str), "%.1fM hits/sec", summary->total_rate/1000000.0);
    }
    
    // Format drop rate
    if (summary->drop_rate < 0.1) {
        snprintf(drop_rate_str, sizeof(drop_rate_str), "0 hits/sec");
    } else if (summary->drop_rate < 1000) {
        snprintf(drop_rate_str, sizeof(drop_rate_str), "%.1f hits/sec", summary->drop_rate);
    } else if (summary->drop_rate < 1000000) {
        snprintf(drop_rate_str, sizeof(drop_rate_str), "%.1fK hits/sec", summary->drop_rate/1000.0);
    } else {
        snprintf(drop_rate_str, sizeof(drop_rate_str), "%.1fM hits/sec", summary->drop_rate/1000000.0);
    }
    
    // Format pass rate
    if (summary->pass_rate < 0.1) {
        snprintf(pass_rate_str, sizeof(pass_rate_str), "0 hits/sec");
    } else if (summary->pass_rate < 1000) {
        snprintf(pass_rate_str, sizeof(pass_rate_str), "%.1f hits/sec", summary->pass_rate);
    } else if (summary->pass_rate < 1000000) {
        snprintf(pass_rate_str, sizeof(pass_rate_str), "%.1fK hits/sec", summary->pass_rate/1000.0);
    } else {
        snprintf(pass_rate_str, sizeof(pass_rate_str), "%.1fM hits/sec", summary->pass_rate/1000000.0);
    }
    
    // Row 2 - Header for total
    mvprintw(y, 2, "%-6s", "Total:");
    mvprintw(y, 10, "%-6d FPs", summary->total_fingerprints);
    mvprintw(y, 25, "%-10s hits", total_hits);
    mvprintw(y, 45, "%s", total_rate_str);
    
    // Draw rate bar
    draw_bar(y, 65, term_cols - 70, summary->total_rate, max_rate, COLOR_PAIR(COLOR_BAR));
    
    y++;
    
    // Row 3 - DROP stats
    attron(COLOR_PAIR(COLOR_DROP));
    mvprintw(y, 2, "%-6s", "DROP:");
    mvprintw(y, 10, "%-6d FPs", summary->drop_fingerprints);
    mvprintw(y, 25, "%-10s hits", drop_hits);
    mvprintw(y, 45, "%s", drop_rate_str);
    
    // Draw a progress bar for DROP action
    int bar_width = 0;
    // Only show a non-empty bar if there are actual hits AND non-zero rate
    if (summary->drop_hits > 0 && summary->drop_rate > 0 && summary->total_fingerprints > 0) {
        double ratio = (double)summary->drop_fingerprints / max_count;
        if (ratio > 1.0) ratio = 1.0;
        bar_width = (int)(ratio * (term_cols - 70));
    }
    
    mvaddch(y, 65, '[');
    attron(COLOR_PAIR(COLOR_DROP));
    for (int i = 0; i < bar_width; i++) {
        mvaddch(y, 66 + i, '#');
    }
    attroff(COLOR_PAIR(COLOR_DROP));
    
    for (int i = bar_width; i < term_cols - 70; i++) {
        mvaddch(y, 66 + i, ' ');
    }
    mvaddch(y, 65 + term_cols - 69, ']');
    
    y++;
    
    // Row 4 - PASS stats
    attron(COLOR_PAIR(COLOR_PASS));
    mvprintw(y, 2, "%-6s", "PASS:");
    mvprintw(y, 10, "%-6d FPs", summary->pass_fingerprints);
    mvprintw(y, 25, "%-10s hits", pass_hits);
    mvprintw(y, 45, "%s", pass_rate_str);
    
    // Draw a progress bar for PASS action
    int pass_bar_width = 0;
    if (summary->pass_hits > 0 && summary->total_fingerprints > 0) {
        // Only show a non-empty bar if there are actual hits
        double ratio = (double)summary->pass_fingerprints / max_count;
        if (ratio > 1.0) ratio = 1.0;
        pass_bar_width = (int)(ratio * (term_cols - 70));
    }
    
    mvaddch(y, 65, '[');
    attron(COLOR_PAIR(COLOR_PASS));
    for (int i = 0; i < pass_bar_width; i++) {
        mvaddch(y, 66 + i, '#');
    }
    attroff(COLOR_PAIR(COLOR_PASS));
    
    for (int i = pass_bar_width; i < term_cols - 70; i++) {
        mvaddch(y, 66 + i, ' ');
    }
    mvaddch(y, 65 + term_cols - 69, ']');
}

/**
 * Draw table header
 */
static void draw_table_header(int y, int term_cols, display_settings_t *settings)
{
    // Draw header line
    attron(A_BOLD);
    mvhline(y, 0, ACS_HLINE, term_cols);
    
    // Column headers
    y++;
    mvprintw(y, 1, "#");
    
    // Highlight the sort column
    if (settings->sort_by == SORT_BY_IP) {
        attron(COLOR_PAIR(COLOR_SORT));
    }
    mvprintw(y, 4, "IP Address");
    if (settings->sort_by == SORT_BY_IP) {
        attroff(COLOR_PAIR(COLOR_SORT));
    }
    
    if (settings->sort_by == SORT_BY_MUONFP) {
        attron(COLOR_PAIR(COLOR_SORT));
    }
    mvprintw(y, 21, "MuonFP");
    if (settings->sort_by == SORT_BY_MUONFP) {
        attroff(COLOR_PAIR(COLOR_SORT));
    }
    
    if (settings->sort_by == SORT_BY_TIME) {
        attron(COLOR_PAIR(COLOR_SORT));
    }
    mvprintw(y, term_cols - 45, "Last Seen");
    if (settings->sort_by == SORT_BY_TIME) {
        attroff(COLOR_PAIR(COLOR_SORT));
    }
    
    if (settings->sort_by == SORT_BY_HITS) {
        attron(COLOR_PAIR(COLOR_SORT));
    }
    mvprintw(y, term_cols - 25, "Hits");
    if (settings->sort_by == SORT_BY_HITS) {
        attroff(COLOR_PAIR(COLOR_SORT));
    }
    
    mvprintw(y, term_cols - 8, "Action");
    attroff(A_BOLD);
    
    // Draw separator line
    y++;
    mvhline(y, 0, ACS_HLINE, term_cols);
}

/**
 * Draw fingerprint table
 */
static void draw_table(fingerprint_entry_t *entries, int count, display_settings_t *settings, 
                       int term_rows, int term_cols)
{
    int base_y = 7;  // Starting row for the table
    
    draw_table_header(base_y, term_cols, settings);
    
    // Calculate visible rows
    int visible_rows = term_rows - base_y - 3;  // Leave room for footer
    if (visible_rows < 1) visible_rows = 1;
    
    // Adjust selected row if needed
    if (settings->selected_row >= count) {
        settings->selected_row = count - 1;
    }
    if (settings->selected_row < 0) {
        settings->selected_row = 0;
    }
    
    // Adjust start row to keep selection visible
    if (settings->selected_row < settings->start_row) {
        settings->start_row = settings->selected_row;
    }
    if (settings->selected_row >= settings->start_row + visible_rows) {
        settings->start_row = settings->selected_row - visible_rows + 1;
    }
    
    // Draw entries
    int y = base_y + 3;  // Start after header
    
    for (int i = 0; i < visible_rows && i + settings->start_row < count; i++) {
        int idx = i + settings->start_row;
        fingerprint_entry_t *entry = &entries[idx];
        
        // Check if this is the selected row
        bool selected = (idx == settings->selected_row);
        if (selected) {
            attron(COLOR_PAIR(COLOR_HIGHLIGHT) | A_BOLD);
        }
        
        // Clear the line
        move(y + i, 0);
        clrtoeol();
        
        // Index
        mvprintw(y + i, 1, "%d", idx + 1);
        
        // IP Address
        attron(COLOR_PAIR(COLOR_IP));
        mvprintw(y + i, 4, "%-15s", entry->ip_str);
        attroff(COLOR_PAIR(COLOR_IP));
        
        // Fingerprint components with color - safely parse the string
        char fp_parts[4][32];
        
        // Initialize all parts to empty strings to avoid garbage
        memset(fp_parts, 0, sizeof(fp_parts));
        
        // Use strtok to safely split the string
        char fp_copy[64];
        strncpy(fp_copy, entry->packet_fp, sizeof(fp_copy) - 1);
        fp_copy[sizeof(fp_copy) - 1] = '\0';
        
        char *token = strtok(fp_copy, ":");
        int part = 0;
        
        while (token != NULL && part < 4) {
            strncpy(fp_parts[part], token, sizeof(fp_parts[0]) - 1);
            fp_parts[part][sizeof(fp_parts[0]) - 1] = '\0';
            part++;
            token = strtok(NULL, ":");
        }
        
        // Fill remaining parts with empty strings
        for (; part < 4; part++) {
            fp_parts[part][0] = '\0';
        }
        
        int fp_x = 21;
        
        // Window size
        attron(COLOR_PAIR(COLOR_WINDOW_SIZE));
        mvprintw(y + i, fp_x, "%s", fp_parts[0]);
        attroff(COLOR_PAIR(COLOR_WINDOW_SIZE));
        fp_x += strlen(fp_parts[0]);
        
        mvprintw(y + i, fp_x, ":");
        fp_x++;
        
        // Options
        attron(COLOR_PAIR(COLOR_OPTIONS));
        mvprintw(y + i, fp_x, "%s", fp_parts[1]);
        attroff(COLOR_PAIR(COLOR_OPTIONS));
        fp_x += strlen(fp_parts[1]);
        
        mvprintw(y + i, fp_x, ":");
        fp_x++;
        
        // MSS
        attron(COLOR_PAIR(COLOR_MSS));
        mvprintw(y + i, fp_x, "%s", fp_parts[2]);
        attroff(COLOR_PAIR(COLOR_MSS));
        fp_x += strlen(fp_parts[2]);
        
        mvprintw(y + i, fp_x, ":");
        fp_x++;
        
        // Window scale
        attron(COLOR_PAIR(COLOR_SCALE));
        mvprintw(y + i, fp_x, "%s", fp_parts[3]);
        attroff(COLOR_PAIR(COLOR_SCALE));
        
        // Last seen time - even more space allocated
        char time_buf[32];
        format_time(entry->actual_time, time_buf, sizeof(time_buf));
        mvprintw(y + i, term_cols - 45, "%s", time_buf);
        
        // Hits with rate - format to fit large numbers (up to 999,999,999)
        char hits_buf[32];
        if (entry->rate > 0) {
            if (entry->rate < 1000) {
                snprintf(hits_buf, sizeof(hits_buf), "%lu (%.0f/s)", entry->stats.count, entry->rate);
            } else if (entry->rate < 1000000) {
                snprintf(hits_buf, sizeof(hits_buf), "%lu (%.1fK/s)", entry->stats.count, entry->rate/1000.0);
            } else {
                snprintf(hits_buf, sizeof(hits_buf), "%lu (%.1fM/s)", entry->stats.count, entry->rate/1000000.0);
            }
        } else {
            snprintf(hits_buf, sizeof(hits_buf), "%lu", entry->stats.count);
        }
        mvprintw(y + i, term_cols - 25, "%-16s", hits_buf);
        
        // Action
        int action_color = (entry->action == XDP_DROP) ? COLOR_DROP : COLOR_PASS;
        attron(COLOR_PAIR(action_color));
        mvprintw(y + i, term_cols - 8, "%-4s", action_to_string(entry->action));
        attroff(COLOR_PAIR(action_color));
        
        if (selected) {
            attroff(COLOR_PAIR(COLOR_HIGHLIGHT) | A_BOLD);
        }
    }
    
    // Draw scrollbar if needed
    if (count > visible_rows) {
        int scrollbar_height = visible_rows;
        int scrollbar_pos = (settings->start_row * visible_rows) / count;
        int scrollbar_size = (visible_rows * visible_rows) / count;
        if (scrollbar_size < 1) scrollbar_size = 1;
        
        for (int i = 0; i < scrollbar_height; i++) {
            if (i >= scrollbar_pos && i < scrollbar_pos + scrollbar_size) {
                mvaddch(y + i, term_cols - 1, ACS_CKBOARD);
            } else {
                mvaddch(y + i, term_cols - 1, ACS_VLINE);
            }
        }
    }
    
    // Draw footer
    mvhline(term_rows - 2, 0, ACS_HLINE, term_cols);
    attron(A_BOLD);
    mvprintw(term_rows - 1, 0, "q:Quit  p/Space:Pause  f:Filter  s:Sort  a:Action  r:Reverse  Up/Down:Navigate  Enter:Details");
    attroff(A_BOLD);
}

/**
 * Draw details panel for selected fingerprint
 */
static void draw_details(fingerprint_entry_t *entry, int term_rows, int term_cols)
{
    // Create a local copy of the entry to prevent issues if data changes while viewing
    fingerprint_entry_t local_entry = *entry;
    
    // Draw header
    attron(COLOR_PAIR(COLOR_HEADER) | A_BOLD);
    mvprintw(0, 0, "Recon Shield Details");
    attroff(COLOR_PAIR(COLOR_HEADER) | A_BOLD);
    
    // Draw details box
    int box_width = term_cols - 4;
    int box_x = 2;
    int box_y = 2;
    
    box(stdscr, 0, 0);
    
    // IP Address (header)
    attron(COLOR_PAIR(COLOR_IP) | A_BOLD);
    mvprintw(box_y, box_x + 2, "IP: %s", local_entry.ip_str);
    attroff(COLOR_PAIR(COLOR_IP) | A_BOLD);
    
    // Draw horizontal line
    mvhline(box_y + 1, box_x + 1, ACS_HLINE, box_width - 2);
    
    int y = box_y + 2;
    
    // Basic fingerprint info
    mvprintw(y++, box_x + 2, "Fingerprint ID:   %d", local_entry.fingerprint_id);
    
    // Detected fingerprint with colors
    mvprintw(y, box_x + 2, "Detected MuonFP:   ");  // Clarify this is what was detected
    
    // Safely parse the detected pattern
    char fp_parts[4][32] = {"", "", "", ""};  // Initialize to empty strings
    
    // Parse the fingerprint using safer method
    char fp_copy[64];
    strncpy(fp_copy, local_entry.packet_fp, sizeof(fp_copy) - 1);
    fp_copy[sizeof(fp_copy) - 1] = '\0';
    
    char *token = strtok(fp_copy, ":");
    int part = 0;
    
    while (token != NULL && part < 4) {
        strncpy(fp_parts[part], token, sizeof(fp_parts[0]) - 1);
        fp_parts[part][sizeof(fp_parts[0]) - 1] = '\0';
        part++;
        token = strtok(NULL, ":");
    }
    
    int fp_x = box_x + 20;
    
    // Window size
    attron(COLOR_PAIR(COLOR_WINDOW_SIZE));
    mvprintw(y, fp_x, "%s", fp_parts[0]);
    attroff(COLOR_PAIR(COLOR_WINDOW_SIZE));
    fp_x += strlen(fp_parts[0]);
    
    mvprintw(y, fp_x, ":");
    fp_x++;
    
    // Options
    attron(COLOR_PAIR(COLOR_OPTIONS));
    mvprintw(y, fp_x, "%s", fp_parts[1]);
    attroff(COLOR_PAIR(COLOR_OPTIONS));
    fp_x += strlen(fp_parts[1]);
    
    mvprintw(y, fp_x, ":");
    fp_x++;
    
    // MSS
    attron(COLOR_PAIR(COLOR_MSS));
    mvprintw(y, fp_x, "%s", fp_parts[2]);
    attroff(COLOR_PAIR(COLOR_MSS));
    fp_x += strlen(fp_parts[2]);
    
    mvprintw(y, fp_x, ":");
    fp_x++;
    
    // Window scale
    attron(COLOR_PAIR(COLOR_SCALE));
    mvprintw(y, fp_x, "%s", fp_parts[3]);
    attroff(COLOR_PAIR(COLOR_SCALE));
    
    y++;
    
    // Matched rule - parse and color the same way as MuonFP
    mvprintw(y, box_x + 2, "Filter Rule:      ");  // Clarify this is the filter rule
    
    // Parse the rule string
    char rule_parts[4][32] = {"", "", "", ""};  // Initialize to empty strings
    
    char rule_copy[64];
    strncpy(rule_copy, local_entry.rule_str, sizeof(rule_copy) - 1);
    rule_copy[sizeof(rule_copy) - 1] = '\0';
    
    // Use a different token variable to avoid redefinition
    char *rule_token = strtok(rule_copy, ":");
    int rule_part = 0;
    
    while (rule_token != NULL && rule_part < 4) {
        strncpy(rule_parts[rule_part], rule_token, sizeof(rule_parts[0]) - 1);
        rule_parts[rule_part][sizeof(rule_parts[0]) - 1] = '\0';
        rule_part++;
        rule_token = strtok(NULL, ":");
    }
    
    int rule_x = box_x + 20;
    
    // Window size (with color)
    attron(COLOR_PAIR(COLOR_WINDOW_SIZE));
    mvprintw(y, rule_x, "%s", rule_parts[0]);
    attroff(COLOR_PAIR(COLOR_WINDOW_SIZE));
    rule_x += strlen(rule_parts[0]);
    
    mvprintw(y, rule_x, ":");
    rule_x++;
    
    // Options (with color)
    attron(COLOR_PAIR(COLOR_OPTIONS));
    mvprintw(y, rule_x, "%s", rule_parts[1]);
    attroff(COLOR_PAIR(COLOR_OPTIONS));
    rule_x += strlen(rule_parts[1]);
    
    mvprintw(y, rule_x, ":");
    rule_x++;
    
    // MSS (with color)
    attron(COLOR_PAIR(COLOR_MSS));
    mvprintw(y, rule_x, "%s", rule_parts[2]);
    attroff(COLOR_PAIR(COLOR_MSS));
    rule_x += strlen(rule_parts[2]);
    
    mvprintw(y, rule_x, ":");
    rule_x++;
    
    // Window scale (with color)
    attron(COLOR_PAIR(COLOR_SCALE));
    mvprintw(y, rule_x, "%s", rule_parts[3]);
    attroff(COLOR_PAIR(COLOR_SCALE));
    
    y++;
    
    // Stats
    mvprintw(y++, box_x + 2, "Statistics:");
    
    // Format hits with suffixes for readability
    char hits_buf[32];
    if (local_entry.stats.count < 1000) {
        snprintf(hits_buf, sizeof(hits_buf), "%lu", local_entry.stats.count);
    } else if (local_entry.stats.count < 1000000) {
        snprintf(hits_buf, sizeof(hits_buf), "%.1fK", local_entry.stats.count / 1000.0);
    } else {
        snprintf(hits_buf, sizeof(hits_buf), "%.1fM", local_entry.stats.count / 1000000.0);
    }
    
    // Format rate with suffixes
    char rate_buf[32];
    if (local_entry.rate < 0.1) {
        snprintf(rate_buf, sizeof(rate_buf), "0 hits/sec");
    } else if (local_entry.rate < 1000) {
        snprintf(rate_buf, sizeof(rate_buf), "%.1f hits/sec", local_entry.rate);
    } else if (local_entry.rate < 1000000) {
        snprintf(rate_buf, sizeof(rate_buf), "%.1fK hits/sec", local_entry.rate/1000.0);
    } else {
        snprintf(rate_buf, sizeof(rate_buf), "%.1fM hits/sec", local_entry.rate/1000000.0);
    }
    
    // Hits and rate
    mvprintw(y++, box_x + 4, "Total Hits:      %s", hits_buf);
    mvprintw(y++, box_x + 4, "Current Rate:    %s", rate_buf);
    
    // Action
    int action_color = (local_entry.action == XDP_DROP) ? COLOR_DROP : COLOR_PASS;
    mvprintw(y, box_x + 4, "Action:          ");
    attron(COLOR_PAIR(action_color) | A_BOLD);
    printw("%s", action_to_string(local_entry.action));
    attroff(COLOR_PAIR(action_color) | A_BOLD);
    y++;
    
    // Time info
    char time_buf[32];
    struct tm *tm = localtime(&local_entry.actual_time);
    if (tm) {
        strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm);
    } else {
        strcpy(time_buf, "Unknown");
    }
    mvprintw(y++, box_x + 4, "Last Seen:       %s", time_buf);
    
    // Raw data section
    y += 2;
    mvprintw(y++, box_x + 2, "Raw Data:");
    mvprintw(y++, box_x + 4, "Window Size:     %u", local_entry.stats.window_size);
    
    // Get the options in the correct order from the matched fingerprint rule
    char opt_str[64] = "";
    
    // Try to get the rule-specified order if we have it in the entry
    if (strlen(local_entry.rule_str) > 0) {
        // Extract the options part from the rule string (the part after first ':' and before second ':')
        char rule_copy[64];
        strncpy(rule_copy, local_entry.rule_str, sizeof(rule_copy) - 1);
        rule_copy[sizeof(rule_copy) - 1] = '\0';
        
        char *parts[4] = {NULL, NULL, NULL, NULL};
        int part_idx = 0;
        
        // Split by ':'
        char *token = strtok(rule_copy, ":");
        while (token != NULL && part_idx < 4) {
            parts[part_idx++] = token;
            token = strtok(NULL, ":");
        }
        
        // If we have the options part (should be index 1)
        if (part_idx > 1 && parts[1] && strcmp(parts[1], "*") != 0) {
            strncpy(opt_str, parts[1], sizeof(opt_str) - 1);
            opt_str[sizeof(opt_str) - 1] = '\0';
        }
    }
    
    // If we couldn't get the ordered options from the rule,
    // fall back to extracting from the bitmap
    if (opt_str[0] == '\0') {
        int pos = 0;
        bool first = true;
        
        for (int opt = 1; opt < 32; opt++) {
            if (local_entry.stats.options_bitmap & (1ULL << opt)) {
                if (!first) {
                    pos += snprintf(opt_str + pos, sizeof(opt_str) - pos, ", ");
                }
                pos += snprintf(opt_str + pos, sizeof(opt_str) - pos, "%d", opt);
                first = false;
                
                if ((size_t)pos >= sizeof(opt_str) - 5) {
                    // If we're about to overflow, add "..." and stop
                    snprintf(opt_str + pos, sizeof(opt_str) - pos, "...");
                    break;
                }
            }
        }
    }
    
    // Print the bitmap (with explanation) and parsed options
    mvprintw(y, box_x + 4, "Options Bitmap:  0x%016lx (internal representation)", local_entry.stats.options_bitmap);
    y++;
    mvprintw(y++, box_x + 4, "TCP Options:     %s", opt_str[0] ? opt_str : "None");
    
    // MSS and window scale
    mvprintw(y++, box_x + 4, "MSS:             %u", local_entry.stats.mss);
    mvprintw(y++, box_x + 4, "Window Scale:    %u", local_entry.stats.window_scale);
    
    // Draw footer
    mvprintw(term_rows - 2, 0, "Press any key to return");
}

/**
 * Get string input from user
 */
static void get_string_input(const char *prompt, char *buf, size_t bufsize, int y, int x)
{
    // Display prompt
    mvprintw(y, x, "%s: ", prompt);
    refresh();
    
    // Enable cursor and echo
    curs_set(1);
    echo();
    
    // Read input
    getnstr(buf, bufsize - 1);
    
    // Disable cursor and echo
    noecho();
    curs_set(0);
}

/**
 * Main monitoring loop
 */
static void monitor_loop(const char *interface, bool interactive)
{
    (void)interactive;  // Unused parameter, silence warning
    
    // Safe initialization of data structures
    printf("Initializing monitor for interface %s...\n", interface);
    
    fingerprint_entry_t entries[MAX_ENTRIES];
    memset(entries, 0, sizeof(entries));
    
    stats_summary_t summary;
    memset(&summary, 0, sizeof(summary));
    
    display_settings_t settings = {
        .show_drop = true,
        .show_pass = true,
        .filter = "",
        .sort_by = SORT_BY_TIME,  // Default sort by time
        .reverse_sort = false,    // Newest first
        .selected_row = 0,
        .show_details = false,
        .start_row = 0,
        .paused = false           // Start unpaused
    };
    
    bool need_redraw = true;  // Force initial draw
    
    // Initialize all entries before we start
    for (int i = 0; i < MAX_ENTRIES; i++) {
        init_fingerprint_entry(&entries[i]);
    }
    
    // Initialize ncurses
    initscr();
    start_color();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(0);  // Hide cursor
    timeout(1000);  // 1 second timeout for getch
    
    // Initialize color pairs
    init_pair(COLOR_NORMAL, COLOR_WHITE, COLOR_BLACK);
    init_pair(COLOR_HIGHLIGHT, COLOR_BLACK, COLOR_WHITE);
    init_pair(COLOR_IP, COLOR_CYAN, COLOR_BLACK);
    init_pair(COLOR_WINDOW_SIZE, COLOR_BLUE, COLOR_BLACK);
    init_pair(COLOR_OPTIONS, COLOR_GREEN, COLOR_BLACK);
    init_pair(COLOR_MSS, COLOR_YELLOW, COLOR_BLACK);
    init_pair(COLOR_SCALE, COLOR_RED, COLOR_BLACK);
    init_pair(COLOR_DROP, COLOR_RED, COLOR_BLACK);
    init_pair(COLOR_PASS, COLOR_GREEN, COLOR_BLACK);
    init_pair(COLOR_HEADER, COLOR_MAGENTA, COLOR_BLACK);
    init_pair(COLOR_SORT, COLOR_YELLOW, COLOR_BLACK);
    init_pair(COLOR_BAR, COLOR_CYAN, COLOR_BLACK);
    
    // Main loop
    while (running) {
        // Get terminal size
        int term_rows, term_cols;
        getmaxyx(stdscr, term_rows, term_cols);
        
        if (term_cols < 80 || term_rows < 15) {
            clear();
            mvprintw(0, 0, "Terminal too small. Need at least 80x15.");
            refresh();
            napms(100);
            continue;
        }
        
        // Collect data only if not paused
        int count;
        if (!settings.paused) {
            count = collect_fingerprint_data(entries, MAX_ENTRIES);
        } else {
            // When paused, use the existing data count
            count = MAX_ENTRIES;
            // Find actual count of initialized entries
            for (count = 0; count < MAX_ENTRIES; count++) {
                if (entries[count].ip == 0) break;
            }
        }
        
        // Always redraw if not paused, or if explicitly needed
        if (!settings.paused || need_redraw) {
            // Process and display data
            // Instead of clear(), only clear specific areas that need updating
            
            // Clear header area (line 0)
            move(0, 0);
            clrtoeol();
            
            // Clear summary area (lines 2-6)
            for (int i = 2; i <= 6; i++) {
                move(i, 0);
                clrtoeol();
            }
            
            // Clear content area from line 7 to bottom
            for (int i = 7; i < term_rows; i++) {
                move(i, 0);
                clrtoeol();
            }
            
            // Process entries (filter and sort)
            count = process_entries(entries, count, &settings);
            
            // Calculate summary statistics
            calculate_summary(entries, count, &summary);
            
            // Draw screen elements
            draw_header(interface, &settings, term_cols);
            draw_summary(&summary, term_cols, COLOR_NORMAL);
            
            // Show details panel or table
            if (settings.show_details && count > 0 && settings.selected_row < count) {
                // Details view needs full screen clear since it completely changes layout
                clear();
                draw_details(&entries[settings.selected_row], term_rows, term_cols);
            } else {
                draw_table(entries, count, &settings, term_rows, term_cols);
            }
            
            refresh();
            need_redraw = false;  // Reset redraw flag
        }
        
        // Check for keyboard input
        int ch = getch();
        if (ch != ERR) {  // If a key was pressed
            need_redraw = true;  // Any key press requires redraw
            if (settings.show_details) {
                // Any key exits details mode
                settings.show_details = false;
            } else {
                // Main screen controls
                switch (ch) {
                    case 'q':
                    case 'Q':
                        running = false;
                        break;
                        
                    case KEY_UP:
                        if (count > 0 && settings.selected_row > 0) {
                            settings.selected_row--;
                        }
                        break;
                        
                    case KEY_DOWN:
                        if (count > 0 && settings.selected_row < count - 1) {
                            settings.selected_row++;
                        }
                        break;
                        
                    case KEY_NPAGE:  // Page Down
                        settings.selected_row += 10;
                        if (settings.selected_row >= count) {
                            settings.selected_row = count - 1;
                        }
                        break;
                        
                    case KEY_PPAGE:  // Page Up
                        settings.selected_row -= 10;
                        if (settings.selected_row < 0) {
                            settings.selected_row = 0;
                        }
                        break;
                        
                    case 10:  // Enter key
                    case 13:
                        if (count > 0) {
                            settings.show_details = true;
                        }
                        break;
                        
                    case 's':  // Toggle sort
                    case 'S':
                        settings.sort_by = (settings.sort_by + 1) % 4;
                        break;
                        
                    case 'r':  // Toggle reverse
                    case 'R':
                        settings.reverse_sort = !settings.reverse_sort;
                        break;
                        
                    case 'a':  // Toggle actions
                    case 'A':
                        if (settings.show_drop && settings.show_pass) {
                            // Show DROP only
                            settings.show_drop = true;
                            settings.show_pass = false;
                        } else if (settings.show_drop) {
                            // Show PASS only
                            settings.show_drop = false;
                            settings.show_pass = true;
                        } else {
                            // Show both
                            settings.show_drop = true;
                            settings.show_pass = true;
                        }
                        settings.selected_row = 0;
                        settings.start_row = 0;
                        break;
                        
                    case 'f':  // Set filter
                    case 'F':
                        get_string_input("Filter", settings.filter, sizeof(settings.filter), 
                                         term_rows - 1, 0);
                        settings.selected_row = 0;
                        settings.start_row = 0;
                        break;
                        
                    case 'p':  // Toggle pause
                    case 'P':
                    case ' ':  // Space bar also toggles pause
                        settings.paused = !settings.paused;
                        break;
                }
            }
        }
    }
    
    // Clean up ncurses
    endwin();
}

/**
 * Display program usage
 */
static void print_usage(const char *prog)
{
    printf("Recon Shield Monitor\n");
    printf("Usage: %s [options] <interface>\n\n"
           "Options:\n"
           "  -i, --interactive      Interactive mode (default)\n"
           "  -d, --debug            Enable debug output\n"
           "  -h, --help             Display this help and exit\n",
           prog);
}

/**
 * Main entry point
 */
int main(int argc, char **argv)
{
    int opt;
    bool interactive = true;  // Default to interactive mode
    bool safe_mode = false;   // For debugging - no ncurses
    
    struct option long_options[] = {
        {"interactive", no_argument, 0, 'i'},
        {"debug", no_argument, 0, 'd'},
        {"help", no_argument, 0, 'h'},
        {"safe", no_argument, 0, 's'},
        {0, 0, 0, 0}
    };
    
    // Parse options
    while ((opt = getopt_long(argc, argv, "idhs", long_options, NULL)) != -1) {
        switch (opt) {
        case 'i':
            interactive = true;
            break;
        case 'd':
            debug = 1;
            break;
        case 's':
            safe_mode = true;
            printf("Running in safe mode (no ncurses)\n");
            break;
        case 'h':
            print_usage(argv[0]);
            return 0;
        default:
            print_usage(argv[0]);
            return 1;
        }
    }
    
    // Check if interface was provided
    if (optind >= argc) {
        fprintf(stderr, "Missing interface argument\n");
        print_usage(argv[0]);
        return 1;
    }
    
    // Get interface
    char *interface = argv[optind];
    
    // Get interface index
    int ifindex = if_nametoindex(interface);
    if (!ifindex) {
        fprintf(stderr, "Invalid interface: %s\n", interface);
        return 1;
    }
    
    // Setup signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    if (safe_mode) {
        // Run in safe mode - just collect data and print without ncurses
        printf("Starting safe mode monitoring for interface %s...\n", interface);
        
        // Initialize arrays
        fingerprint_entry_t entries[MAX_ENTRIES];
        for (int i = 0; i < MAX_ENTRIES; i++) {
            init_fingerprint_entry(&entries[i]);
        }
        
        // Just collect entries once
        int count = collect_fingerprint_data(entries, MAX_ENTRIES);
        printf("Found %d active fingerprint entries\n", count);
        
        // Print basic info about each entry
        for (int i = 0; i < count; i++) {
            printf("Entry %d: IP=%s, FP_ID=%d, Action=%s, Hits=%lu\n",
                   i, entries[i].ip_str, entries[i].fingerprint_id,
                   action_to_string(entries[i].action), entries[i].stats.count);
        }
        
        printf("Safe mode monitoring completed.\n");
    } else {
        // Start normal monitoring loop with ncurses UI
        monitor_loop(interface, interactive);
    }
    
    return 0;
}
