/**
 * TCP Fingerprint Firewall
 * Control Program for eBPF-based TCP fingerprinting and filtering
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
#include <limits.h>  /* For INT_MAX */

// Define constants
#define MAP_PATH_BASE "/sys/fs/bpf"
#define XDP_PASS 2
#define XDP_DROP 1

// Field check bits (must match eBPF program)
#define CHECK_WINDOW_SIZE  (1 << 0)
#define CHECK_OPTIONS      (1 << 1)
#define CHECK_MSS          (1 << 2)
#define CHECK_WINDOW_SCALE (1 << 3)

// Format strings for output
#define IP_TABLE_FORMAT "%-17s %-10u %-10u %-7u %-7u %-10lu\n"
#define FP_TABLE_FORMAT "%-4d %-15s %-15s %-15s %-15s %-6s\n"

// Global control flags
static volatile bool running = true;
static int debug = 0;

/**
 * TCP Fingerprint structure (must match eBPF program)
 * Supports both basic option matching and complex option sequence matching
 * for precise fingerprint identification
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
    
    // Note: The options field in MuonFP can be:
    // - "*": any options are allowed (don't check options)
    // - "": no options allowed (options_kind=0, fields_to_check has CHECK_OPTIONS)
    // - "2": only option 2 (MSS) is allowed, exactly (options_kind=2, fields_to_check has CHECK_OPTIONS)
    // - "2-3-4": complex options string; this now uses the options_sequence array
};

/**
 * Composite key structure for multi-fingerprint tracking
 * Allows tracking multiple distinct fingerprints per IP address
 * (must match eBPF program)
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

/**
 * Signal handler for clean termination
 */
static void signal_handler(int signo)
{
    running = false;
}

/**
 * Display program usage
 */
static void print_usage(const char *prog)
{
    printf("TCP Fingerprint Firewall\n");
    printf("Usage: %s [options] <interface> <command>\n\n"
           "Commands:\n"
           "  load                      Load XDP firewall program\n"
           "  unload                    Unload XDP firewall program\n"
           "  show                      Show matched IPs and their fingerprints\n"
           "  add <pattern> <action>    Add fingerprint pattern with specified action\n"
           "  remove <id>               Remove fingerprint pattern by ID\n"
           "  list                      List configured fingerprint patterns\n"
           "  clear                     Clear all fingerprints and matched IPs\n\n"
           "Options:\n"
           "  -d, --debug               Enable debug output\n"
           "  -c, --continuous          Continuous monitoring mode (updates every second)\n"
           "  -a, --default-action <action>  Set default action (DROP/PASS)\n"
           "  -o, --obj <filename>      Specify custom BPF object file path\n\n"
           "Pattern format: window_size:options:mss:window_scale\n"
           "  Example: 1024:::          Match Nmap scanner (window size 1024, no options)\n"
           "  Example: 65535:::         Match Zmap scanner (window size 65535, no options)\n"
           "  Example: *:2:1460:*       Match any window size with MSS option 1460\n"
           "  Example: 64240:2-4-8-1-3:1460:7  Match specific sequence of TCP options\n\n"
           "  Use * for any value (wildcard), empty field for absent value\n\n"
           "TCP Option Patterns:\n"
           "  - Empty field (:):        No options allowed (e.g., 1024:::)\n"
           "  - Single number (2):      Only that specific option must be present\n"
           "  - Hyphenated (2-4-8-1-3): Exact sequence of options required\n"
           "  - Wildcard (*):           Any options allowed\n\n"
           "Compatibility Notes:\n"
           "  If you encounter issues loading the program, try:\n"
           "  1. Running with sudo\n"
           "  2. Use SKB mode on unsupported network cards\n",
           prog);
}

/**
 * Custom libbpf print function
 */
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG && !debug)
        return 0;
    return vfprintf(stderr, format, args);
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
 * Parse action string to value
 */
static uint8_t string_to_action(const char *action)
{
    if (strcasecmp(action, "DROP") == 0)
        return XDP_DROP;
    else
        return XDP_PASS;
}

/**
 * Parse fingerprint pattern string into structure
 * Format: window_size:option:mss:window_scale
 */
static int parse_fingerprint(const char *pattern, uint8_t action, struct tcp_fingerprint *fp)
{
    // Handle trailing colon (empty field) case
    // Look for patterns ending with a colon, which strtok won't handle correctly
    bool trailing_colon = false;
    size_t len = strlen(pattern);
    if (len > 0 && pattern[len - 1] == ':') {
        trailing_colon = true;
    }
    
    char *pattern_copy = strdup(pattern);
    if (!pattern_copy) {
        fprintf(stderr, "Failed to allocate memory\n");
        return -1;
    }
    
    // Initialize fingerprint structure
    memset(fp, 0, sizeof(*fp));
    fp->action = action;
    
    if (debug) {
        printf("Processing fingerprint pattern: '%s'\n", pattern);
    }
    
    // Special case for common fingerprints
    // Special handling for some common pattern templates
    if (strcmp(pattern, "1024:::") == 0) {
        // Nmap scanner pattern - window 1024, no options, no MSS, no window scale
        fp->window_size = 1024;
        fp->options_kind = 0;
        fp->mss = 0;
        fp->window_scale = 0;
        fp->fields_to_check = CHECK_WINDOW_SIZE | CHECK_OPTIONS | CHECK_MSS | CHECK_WINDOW_SCALE;
        fp->sequence_len = 0; // No sequence
        free(pattern_copy);
        return 0;
    }
    
    if (strcmp(pattern, "65535:::") == 0) {
        // Zmap scanner pattern - window 65535, no options, no MSS, no window scale
        fp->window_size = 65535;
        fp->options_kind = 0;
        fp->mss = 0;
        fp->window_scale = 0;
        fp->fields_to_check = CHECK_WINDOW_SIZE | CHECK_OPTIONS | CHECK_MSS | CHECK_WINDOW_SCALE;
        fp->sequence_len = 0; // No sequence
        free(pattern_copy);
        return 0;
    }
    
    // Parse pattern components
    char *window_str = strtok(pattern_copy, ":");
    char *option_str = strtok(NULL, ":");
    char *mss_str = strtok(NULL, ":");
    char *wscale_str = strtok(NULL, ":");
    
    if (debug) {
        printf("Pattern: '%s'\n", pattern);
        printf("  window_str: '%s'\n", window_str ? window_str : "(null)");
        printf("  option_str: '%s'\n", option_str ? option_str : "(null)");
        printf("  mss_str: '%s'\n", mss_str ? mss_str : "(null)");
        printf("  wscale_str: '%s'\n", wscale_str ? wscale_str : "(null)");
    }
    
    // Parse window size
    if (window_str && *window_str && strcmp(window_str, "*") != 0) {
        fp->window_size = atoi(window_str);
        fp->fields_to_check |= CHECK_WINDOW_SIZE;
    }
    
    // Parse options
    if (option_str) {
        if (option_str[0] == '\0') {
            // Empty field - no options allowed
            fp->options_kind = 0;
            fp->fields_to_check |= CHECK_OPTIONS;
            fp->sequence_len = 0;
        } else if (strcmp(option_str, "*") != 0) {
            // Check if this is a basic option number or a complex option string with hyphens
            if (strchr(option_str, '-') == NULL) {
                // Single option number (like "2")
                fp->options_kind = atoi(option_str);
                fp->fields_to_check |= CHECK_OPTIONS;
                fp->sequence_len = 0; // Not using sequence for basic option
                
                if (debug) {
                    printf("  Basic option number: %d\n", fp->options_kind);
                }
            } else {
                // Complex option string like "2-4-8-1-3"
                // Parse the hyphen-separated values into the sequence array
                
                char *opts_copy = strdup(option_str);
                if (!opts_copy) {
                    fprintf(stderr, "Failed to allocate memory for options parsing\n");
                    free(pattern_copy);
                    return -1;
                }
                
                // Parse the hyphen-separated values
                char *token = strtok(opts_copy, "-");
                uint8_t idx = 0;
                
                while (token && idx < 16) {  // Maximum 16 options in sequence
                    uint8_t opt_val = atoi(token);
                    if (opt_val > 0 && opt_val < 64) {  // Valid TCP option range
                        fp->options_sequence[idx++] = opt_val;
                    }
                    token = strtok(NULL, "-");
                }
                
                fp->sequence_len = idx;  // Store how many options we found
                free(opts_copy);  // Always free the allocated memory
                
                // Mark this as a complex pattern (for backward compatibility)
                fp->options_kind = 255;
                
                // We're now using the sequence fields, so we don't set CHECK_OPTIONS
                // fp->fields_to_check |= CHECK_OPTIONS;
                
                if (debug) {
                    printf("  Complex option string: '%s' - Implementing exact option sequence matching\n", 
                           option_str);
                    printf("  Parsed %d options: ", fp->sequence_len);
                    for (int i = 0; i < fp->sequence_len; i++) {
                        printf("%d ", fp->options_sequence[i]);
                    }
                    printf("\n");
                }
            }
        } else {
            // "*" wildcard - no specific option requirements
            fp->sequence_len = 0;
        }
    }
    
    // Parse MSS
    if (mss_str) {
        if (mss_str[0] == '\0') {
            // Empty field - no MSS option allowed
            fp->mss = 0;
            fp->fields_to_check |= CHECK_MSS;
        } else if (strcmp(mss_str, "*") != 0) {
            // Specific MSS value
            fp->mss = atoi(mss_str);
            fp->fields_to_check |= CHECK_MSS;
        }
    }
    
    // Parse window scale
    if (wscale_str) {
        if (wscale_str[0] == '\0') {
            // Empty field - no window scale option allowed
            fp->window_scale = 0;
            fp->fields_to_check |= CHECK_WINDOW_SCALE;
        } else if (strcmp(wscale_str, "*") != 0) {
            // Specific window scale value
            fp->window_scale = atoi(wscale_str);
            fp->fields_to_check |= CHECK_WINDOW_SCALE;
        }
    } else if (trailing_colon) {
        // Handle trailing colon case (empty window scale field)
        fp->window_scale = 0;
        fp->fields_to_check |= CHECK_WINDOW_SCALE;
    }
    
    // Check for patterns with 3 or more colons but potentially missing the fourth field
    // E.g., "*:2:1460:" which should be parsed with empty window scale field
    if (wscale_str == NULL) {
        int colon_count = 0;
        for (size_t i = 0; i < len; i++) {
            if (pattern[i] == ':') colon_count++;
        }
        
        // If the pattern has at least 3 colons and ends with a colon, it means 
        // there's an empty window scale field
        if (colon_count >= 3 && pattern[len-1] == ':') {
            fp->window_scale = 0;
            fp->fields_to_check |= CHECK_WINDOW_SCALE;
            if (debug) printf("Added empty window scale field for pattern ending with ':'\n");
        }
    }
    
    // For debugging - this is extremely useful for diagnosing pattern issues
    if (debug) {
        printf("Parsed pattern '%s':\n", pattern);
        printf("  Window Size: %u (checked: %s)\n", 
               fp->window_size, (fp->fields_to_check & CHECK_WINDOW_SIZE) ? "yes" : "no");
        
        if (fp->sequence_len > 0) {
            printf("  Options: Complex sequence with %d options (", fp->sequence_len);
            for (int i = 0; i < fp->sequence_len; i++) {
                printf("%d", fp->options_sequence[i]);
                if (i < fp->sequence_len - 1) printf("-");
            }
            printf(")\n");
        } else {
            printf("  Options Kind: %u (checked: %s)\n", 
                   fp->options_kind, (fp->fields_to_check & CHECK_OPTIONS) ? "yes" : "no");
        }
        
        printf("  MSS: %u (checked: %s)\n", 
               fp->mss, (fp->fields_to_check & CHECK_MSS) ? "yes" : "no");
        printf("  Window Scale: %u (checked: %s)\n", 
               fp->window_scale, (fp->fields_to_check & CHECK_WINDOW_SCALE) ? "yes" : "no");
    }
    
    free(pattern_copy);
    return 0;
}

// Function removed as it's not used in the current implementation

/**
 * Display list of fingerprints
 */
static void list_fingerprints(int fp_map, int config_map)
{
    // Read configuration
    uint32_t key = 0;
    struct config cfg;
    if (bpf_map_lookup_elem(config_map, &key, &cfg) != 0) {
        fprintf(stderr, "Failed to read configuration\n");
        return;
    }
    
    printf("TCP Fingerprint Firewall Configuration\n");
    printf("---------------------------------------\n");
    printf("Active fingerprints: %u\n", cfg.fingerprint_count);
    printf("Default action: %s\n", action_to_string(cfg.default_action));
    printf("Total matches: %u\n", cfg.total_matches);
    if (debug) {
        printf("Debug reserved field: %u (last seen window size)\n", cfg.reserved);
    }
    printf("\n");
    
    if (cfg.fingerprint_count == 0) {
        printf("No fingerprints defined\n");
        return;
    }
    
    // Print header
    printf("%-4s %-15s %-15s %-15s %-15s %-6s\n", "ID", "Window Size", "Options", "MSS", "Window Scale", "Action");
    printf("--------------------------------------------------------------------\n");
    
    // Print each fingerprint
    for (int i = 0; i < cfg.fingerprint_count; i++) {
        uint32_t idx = i;
        struct tcp_fingerprint fp;
        
        if (bpf_map_lookup_elem(fp_map, &idx, &fp) != 0) {
            fprintf(stderr, "Failed to read fingerprint %d\n", i);
            continue;
        }
        
        // Format fields
        char window_str[16] = "*";
        char option_str[32] = "*";  // Increased size for composite option strings
        char mss_str[16] = "*";
        char wscale_str[16] = "*";
        
        if (fp.fields_to_check & CHECK_WINDOW_SIZE)
            snprintf(window_str, sizeof(window_str), "%u", fp.window_size);
            
        if (fp.sequence_len > 0) {
            // Handle complex option sequences
            char seq_buf[32] = {0};
            int pos = 0;
            
            // Format the sequence as hyphen-separated values
            for (int i = 0; i < fp.sequence_len && i < 16; i++) {
                if (i > 0)
                    pos += snprintf(seq_buf + pos, sizeof(seq_buf) - pos, "-");
                pos += snprintf(seq_buf + pos, sizeof(seq_buf) - pos, "%d", fp.options_sequence[i]);
            }
            
            snprintf(option_str, sizeof(option_str), "%s", seq_buf);
        } else if (fp.fields_to_check & CHECK_OPTIONS) {
            if (fp.options_kind == 0)
                snprintf(option_str, sizeof(option_str), "none");
            else if (fp.options_kind == 255)
                snprintf(option_str, sizeof(option_str), "complex");
            else
                snprintf(option_str, sizeof(option_str), "%u", fp.options_kind);
        } else if (fp.options_kind == 255) {
            // Special case for composite options without the check flag
            snprintf(option_str, sizeof(option_str), "complex");
        }
        
        if (fp.fields_to_check & CHECK_MSS) {
            if (fp.mss == 0)
                snprintf(mss_str, sizeof(mss_str), "none");
            else
                snprintf(mss_str, sizeof(mss_str), "%u", fp.mss);
        }
            
        if (fp.fields_to_check & CHECK_WINDOW_SCALE) {
            if (fp.window_scale == 0)
                snprintf(wscale_str, sizeof(wscale_str), "none");
            else
                snprintf(wscale_str, sizeof(wscale_str), "%u", fp.window_scale);
        }
        
        // Print formatted line
        printf(FP_TABLE_FORMAT, i, window_str, option_str, mss_str, wscale_str, 
               action_to_string(fp.action));
    }
}

/**
 * Format a TCP fingerprint rule in MuonFP format
 * Converts internal fingerprint structure to window_size:options:mss:window_scale format
 * with proper wildcard handling
 */
static void format_muonfp(const struct tcp_fingerprint *fp, char *buf, size_t bufsize);

/**
 * Format options bitmap into a hyphen-separated string
 * Converts a 64-bit bitmap of TCP options into a string like "2-4-8"
 */
static void format_options_bitmap(uint64_t bitmap, char *buf, size_t bufsize);

/**
 * Format a packet's TCP fingerprint into MuonFP format
 * Converts raw packet statistics into standardized window_size:options:mss:window_scale format
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
    
    // Check if MSS is present (TCP option 2)
    char mss_str[16] = "";
    if (stats->options_bitmap & (1ULL << 2)) {
        snprintf(mss_str, sizeof(mss_str), "%u", stats->mss);
    }
    
    // Check if window scale is present (TCP option 3)
    char wscale_str[16] = "";
    if (stats->options_bitmap & (1ULL << 3)) {
        snprintf(wscale_str, sizeof(wscale_str), "%u", stats->window_scale);
    }
    
    // Format without colors
    snprintf(buf, bufsize, "%u:%s:%s:%s", 
            stats->window_size,
            options_str,
            mss_str,
            wscale_str);
}

/**
 * Format options bitmap into a hyphen-separated string
 * Converts a 64-bit bitmap of TCP options into a string like "2-4-8"
 */
static void format_options_bitmap(uint64_t bitmap, char *buf, size_t bufsize)
{
    if (bitmap > 0) {
        int pos = 0;
        bool has_options = false;
        
        for (int opt = 1; opt < 32; opt++) {  // Skip option 0 (end of options)
            if (bitmap & (1ULL << opt)) {
                // Check if we have space for at least 5 more chars (for "-NNN\0" worst case)
                if (pos >= (int)bufsize - 5) {
                    break;  // Not enough space left in buffer
                }

                if (has_options) {
                    int chars_written = snprintf(buf + pos, bufsize - pos, "-");
                    if (chars_written < 0 || chars_written >= (int)(bufsize - pos)) {
                        break;  // Avoid buffer overflow
                    }
                    pos += chars_written;
                }
                
                int chars_written = snprintf(buf + pos, bufsize - pos, "%d", opt);
                if (chars_written < 0 || chars_written >= (int)(bufsize - pos)) {
                    break;  // Avoid buffer overflow
                }
                pos += chars_written;
                has_options = true;
            }
        }
        
        // Ensure null termination
        if (bufsize > 0) {
            buf[bufsize - 1] = '\0';
        }
    } else {
        if (bufsize > 0) {
            buf[0] = '\0';  // Empty string if no options
        }
    }
}

/**
 * Calculate visible length of a string by excluding ANSI color escape sequences
 * Essential for proper text alignment when using colored text in terminal output
 */
static int get_visible_length(const char *str)
{
    int len = 0;
    bool in_escape = false;
    
    for (int i = 0; str[i] != '\0'; i++) {
        if (str[i] == '\033') {
            in_escape = true;
        } else if (in_escape && str[i] == 'm') {
            in_escape = false;
        } else if (!in_escape) {
            len++;
        }
    }
    return len;
}

/**
 * Print a colored string with proper padding to fill a specific width
 * Accounts for invisible ANSI color codes when calculating padding
 */
static void print_padded_colored(const char *str, int width)
{
    printf("%s", str);
    int visible_len = get_visible_length(str);
    for (int i = 0; i < width - visible_len; i++) {
        printf(" ");
    }
}

/**
 * Format matched rule information and retrieve the associated fingerprint structure
 * Used to provide user-friendly rule representation for display purposes
 */
static bool format_matched_rule(int fp_map, uint8_t fp_id, char *rule_buf, char *action_buf, struct tcp_fingerprint *result_fp)
{
    strcpy(rule_buf, "Unknown");
    strcpy(action_buf, "?");
    bool success = false;
    
    if (fp_id < 64) {
        uint32_t fp_key = fp_id;
        struct tcp_fingerprint fp;
        
        if (bpf_map_lookup_elem(fp_map, &fp_key, &fp) == 0) {
            format_muonfp(&fp, rule_buf, 64);
            strncpy(action_buf, action_to_string(fp.action), 8);
            
            if (result_fp) {
                *result_fp = fp;  // Copy the fingerprint structure
                success = true;
            }
        }
    }
    
    return success;
}

/**
 * Format a TCP fingerprint rule in MuonFP format
 * Converts internal fingerprint structure to window_size:options:mss:window_scale format
 * with proper wildcard handling
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
 * Display list of matched IPs and their fingerprints in tabular format
 * Supports displaying multiple fingerprints per IP with color-coded components
 */
static void list_ips(int ip_map, int fp_map, int config_map, bool continuous)
{
    // Maps paths
    char multi_fingerprint_path[256];
    snprintf(multi_fingerprint_path, sizeof(multi_fingerprint_path), "%s/multi_fingerprint_ips", 
             "/sys/fs/bpf");
             
    // First try to open the multi-fingerprint map
    int multi_fp_map = bpf_obj_get(multi_fingerprint_path);
    bool using_multi_map = (multi_fp_map >= 0);
    
    // Read all IPs from the map
    int count = 0;
    uint32_t key, next_key;
    struct ip_stats stats;
    
    if (continuous) {
        printf("\033[2J\033[H");  // Clear screen
    }
    
    // Get config for total matches and print header
    uint32_t cfg_key = 0;
    struct config cfg;
    
    // Count entries in legacy map
    key = 0;
    while (bpf_map_get_next_key(ip_map, &key, &next_key) == 0) {
        count++;
        key = next_key;
    }
    
    if (count == 0) {
        printf("TCP Fingerprint Firewall - Matched IPs\n");
        printf("=======================================\n");
        printf("No packets matched\n");
        if (using_multi_map) {
            close(multi_fp_map);
        }
        return;
    }
    
    // Print header
    printf("TCP Fingerprint Firewall - Matched IPs\n");
    printf("=======================================\n");
    
    // Print total matches if available
    if (bpf_map_lookup_elem(config_map, &cfg_key, &cfg) == 0) {
        printf("Total matches: %u\n", cfg.total_matches);
    }
    
    // First, collect all unique IPs
    struct {
        uint32_t ip;
        uint64_t latest_timestamp;
        int count;  // Number of different fingerprints for this IP
    } unique_ips[10];  // Store up to 10 different source IPs
    
    memset(unique_ips, 0, sizeof(unique_ips));
    int ip_count = 0;
    
    // First pass: collect unique IPs with their latest timestamp from legacy map
    key = 0;
    while (bpf_map_get_next_key(ip_map, &key, &next_key) == 0 && ip_count < 10) {
        if (bpf_map_lookup_elem(ip_map, &next_key, &stats) == 0) {
            // Check if this IP is already in our list
            bool found = false;
            for (int i = 0; i < ip_count; i++) {
                if (unique_ips[i].ip == next_key) {
                    // Update timestamp if newer
                    if (stats.timestamp > unique_ips[i].latest_timestamp) {
                        unique_ips[i].latest_timestamp = stats.timestamp;
                    }
                    unique_ips[i].count++;
                    found = true;
                    break;
                }
            }
            
            // Add new IP if not found
            if (!found) {
                unique_ips[ip_count].ip = next_key;
                unique_ips[ip_count].latest_timestamp = stats.timestamp;
                unique_ips[ip_count].count = 1;
                ip_count++;
            }
        }
        key = next_key;
    }
    
    // Sort IPs by latest timestamp (most recent first)
    for (int i = 0; i < ip_count - 1; i++) {
        for (int j = 0; j < ip_count - i - 1; j++) {
            if (unique_ips[j].latest_timestamp < unique_ips[j + 1].latest_timestamp) {
                // Swap
                uint32_t temp_ip = unique_ips[j].ip;
                uint64_t temp_ts = unique_ips[j].latest_timestamp;
                int temp_count = unique_ips[j].count;
                
                unique_ips[j].ip = unique_ips[j + 1].ip;
                unique_ips[j].latest_timestamp = unique_ips[j + 1].latest_timestamp;
                unique_ips[j].count = unique_ips[j + 1].count;
                
                unique_ips[j + 1].ip = temp_ip;
                unique_ips[j + 1].latest_timestamp = temp_ts;
                unique_ips[j + 1].count = temp_count;
            }
        }
    }
    
    // Second pass: for each unique IP, collect up to 5 most recent fingerprints
    for (int ip_idx = 0; ip_idx < ip_count; ip_idx++) {
        uint32_t current_ip = unique_ips[ip_idx].ip;
        
        // Convert IP to string once for display
        char ip_str[INET_ADDRSTRLEN];
        struct in_addr addr = { .s_addr = current_ip };
        inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
        
        // Structure to store different fingerprints for this IP
        struct {
            struct ip_stats stats;
            uint8_t fingerprint_id;
            uint64_t timestamp;
            char packet_fp[64];
            char matched_rule[64];
            char action_str[8];
        } fingerprints[5];  // Store up to 5 different fingerprints
        
        memset(fingerprints, 0, sizeof(fingerprints));
        int fp_count = 0;
        
        if (using_multi_map) {
            // Use the multi-fingerprint map to get all fingerprints for this IP
            struct ip_fp_key multi_key, next_multi_key;
            memset(&multi_key, 0, sizeof(multi_key));
            
            // Find all fingerprints for this IP
            while (bpf_map_get_next_key(multi_fp_map, &multi_key, &next_multi_key) == 0 && fp_count < 5) {
                // Check if this is our IP
                if (next_multi_key.ip == current_ip) {
                    // Get the stats for this IP+fingerprint combination
                    struct ip_stats multi_stats;
                    if (bpf_map_lookup_elem(multi_fp_map, &next_multi_key, &multi_stats) == 0) {
                        // Add this fingerprint to our list
                        fingerprints[fp_count].stats = multi_stats;
                        fingerprints[fp_count].fingerprint_id = next_multi_key.fingerprint_id;
                        fingerprints[fp_count].timestamp = multi_stats.timestamp;
                        
                        // Format packet fingerprint
                        format_packet_fingerprint(&multi_stats, next_multi_key.fingerprint_id, 
                                               fingerprints[fp_count].packet_fp, 
                                               sizeof(fingerprints[fp_count].packet_fp));
                        
                        // Get matched rule
                        struct tcp_fingerprint matched_fp;
                        if (format_matched_rule(fp_map, next_multi_key.fingerprint_id, 
                                             fingerprints[fp_count].matched_rule, 
                                             fingerprints[fp_count].action_str,
                                             &matched_fp)) {
                            // Rule info is now stored in the fingerprints array
                        }
                        
                        fp_count++;
                    }
                }
                multi_key = next_multi_key;
            }
        }
        
        // If we didn't find any fingerprints in the multi-map or it's not available, 
        // fall back to the legacy map
        if (fp_count == 0) {
            // First, retrieve the actual entry for this IP from the legacy map
            if (bpf_map_lookup_elem(ip_map, &current_ip, &stats) == 0) {
                // Get fingerprint ID from legacy map
                uint8_t fingerprint_id = 0;
                
                // Since the fingerprint_id field was removed from ip_stats, we need to
                // find it by checking for a match in the multi-fingerprint map, or use 0 as default
                if (using_multi_map) {
                    struct ip_fp_key multi_key, next_multi_key;
                    memset(&multi_key, 0, sizeof(multi_key));
                    
                    while (bpf_map_get_next_key(multi_fp_map, &multi_key, &next_multi_key) == 0) {
                        if (next_multi_key.ip == current_ip) {
                            fingerprint_id = next_multi_key.fingerprint_id;
                            break;
                        }
                        multi_key = next_multi_key;
                    }
                }
                
                // Add the entry from the legacy map
                fingerprints[fp_count].stats = stats;
                fingerprints[fp_count].fingerprint_id = fingerprint_id;
                fingerprints[fp_count].timestamp = stats.timestamp;
                
                // Format packet fingerprint
                format_packet_fingerprint(&stats, fingerprint_id, fingerprints[fp_count].packet_fp, 
                                       sizeof(fingerprints[fp_count].packet_fp));
                
                // Get matched rule
                struct tcp_fingerprint matched_fp;
                if (format_matched_rule(fp_map, fingerprint_id, 
                                     fingerprints[fp_count].matched_rule, 
                                     fingerprints[fp_count].action_str,
                                     &matched_fp)) {
                    // Rule info is now stored in the fingerprints array
                }
                
                fp_count++;
            }
        }
        
        // Sort fingerprints by timestamp (most recent first)
        for (int i = 0; i < fp_count - 1; i++) {
            for (int j = 0; j < fp_count - i - 1; j++) {
                if (fingerprints[j].timestamp < fingerprints[j + 1].timestamp) {
                    // Create a temporary copy using individual fields
                    struct ip_stats temp_stats = fingerprints[j].stats;
                    uint8_t temp_fp_id = fingerprints[j].fingerprint_id;
                    uint64_t temp_ts = fingerprints[j].timestamp;
                    char temp_packet_fp[64], temp_rule[64], temp_action[8];
                    
                    strcpy(temp_packet_fp, fingerprints[j].packet_fp);
                    strcpy(temp_rule, fingerprints[j].matched_rule);
                    strcpy(temp_action, fingerprints[j].action_str);
                    
                    // Copy j+1 to j
                    fingerprints[j].stats = fingerprints[j + 1].stats;
                    fingerprints[j].fingerprint_id = fingerprints[j + 1].fingerprint_id;
                    fingerprints[j].timestamp = fingerprints[j + 1].timestamp;
                    strcpy(fingerprints[j].packet_fp, fingerprints[j + 1].packet_fp);
                    strcpy(fingerprints[j].matched_rule, fingerprints[j + 1].matched_rule);
                    strcpy(fingerprints[j].action_str, fingerprints[j + 1].action_str);
                    
                    // Copy temp to j+1
                    fingerprints[j + 1].stats = temp_stats;
                    fingerprints[j + 1].fingerprint_id = temp_fp_id;
                    fingerprints[j + 1].timestamp = temp_ts;
                    strcpy(fingerprints[j + 1].packet_fp, temp_packet_fp);
                    strcpy(fingerprints[j + 1].matched_rule, temp_rule);
                    strcpy(fingerprints[j + 1].action_str, temp_action);
                }
            }
        }
        

        // IP string should already be set from earlier code
        
        // Print IP header
        printf("\n\033[1mIP: %s\033[0m\n", ip_str);
        
        // If no fingerprints (should not happen), continue to next IP
        if (fp_count == 0) continue;
        
        // Define table column widths
        const int ID_WIDTH = 4;
        const int FP_WIDTH = 35;
        const int RULE_WIDTH = 34;
        const int HITS_WIDTH = 8;
        const int TIME_WIDTH = 19;
        
        // Print table header - use ASCII only for better terminal compatibility
        printf("+%.*s+%.*s+%.*s+%.*s+%.*s+\n", 
               ID_WIDTH, "---------------------", 
               FP_WIDTH, "-------------------------------------------", 
               RULE_WIDTH, "-------------------------------------------", 
               HITS_WIDTH, "----------------", 
               TIME_WIDTH, "-------------------");
               
        printf("| %-*s | %-*s | %-*s | %-*s | %-*s |\n", 
               ID_WIDTH-2, "#", 
               FP_WIDTH-2, "Detected", 
               RULE_WIDTH-2, "Matched Rule", 
               HITS_WIDTH-2, "Hits", 
               TIME_WIDTH-2, "Last Seen");
               
        printf("+%.*s+%.*s+%.*s+%.*s+%.*s+\n", 
               ID_WIDTH, "---------------------", 
               FP_WIDTH, "-------------------------------------------", 
               RULE_WIDTH, "-------------------------------------------", 
               HITS_WIDTH, "----------------", 
               TIME_WIDTH, "-------------------");
        
        // For each fingerprint, print in compact table format
        for (int i = 0; i < fp_count; i++) {
            // Parse the packet fingerprint into components
            char fp_parts[4][32] = {"", "", "", ""};  // window, options, mss, wscale
            sscanf(fingerprints[i].packet_fp, "%[^:]:%[^:]:%[^:]:%s", 
                   fp_parts[0], fp_parts[1], fp_parts[2], fp_parts[3]);
                   
            // Parse the rule into components
            char rule_parts[4][32] = {"", "", "", ""}; // window, options, mss, wscale
            sscanf(fingerprints[i].matched_rule, "%[^:]:%[^:]:%[^:]:%s", 
                   rule_parts[0], rule_parts[1], rule_parts[2], rule_parts[3]);
            
            // Get timestamp string (always, not just in debug mode)
            time_t current_time = time(NULL);  // Get current time in seconds
            time_t uptime_secs = 0;
            
            // Get system uptime from /proc/uptime
            FILE *uptime_file = fopen("/proc/uptime", "r");
            if (uptime_file) {
                float uptime;
                if (fscanf(uptime_file, "%f", &uptime) == 1) {
                    uptime_secs = (time_t)uptime;
                }
                fclose(uptime_file);
            }
            
            // The timestamp is nanoseconds since boot, so we need to:
            // 1. Convert ns to seconds
            // 2. Calculate actual time by subtracting uptime from current time and adding timestamp
            time_t timestamp_secs = fingerprints[i].timestamp / 1000000000;
            time_t actual_time = current_time - uptime_secs + timestamp_secs;
            
            // Convert to local time
            struct tm *tm = localtime(&actual_time);
            
            // Format time string to shorter format for table
            char short_time_str[32];
            if (tm && actual_time > 0) {
                strftime(short_time_str, sizeof(short_time_str), "%H:%M:%S %y-%m-%d", tm);
            } else {
                strcpy(short_time_str, "Unknown");
            }
            
            // Create colored fingerprint and rule strings
            char colored_fp[256], colored_rule[256];
            
            // Format colored strings with each part having its distinct color
            snprintf(colored_fp, sizeof(colored_fp), "\033[34m%s\033[0m:\033[32m%s\033[0m:\033[33m%s\033[0m:\033[31m%s\033[0m", 
                   fp_parts[0], fp_parts[1], fp_parts[2], fp_parts[3]);
                   
            snprintf(colored_rule, sizeof(colored_rule), "\033[34m%s\033[0m:\033[32m%s\033[0m:\033[33m%s\033[0m:\033[31m%s\033[0m", 
                   rule_parts[0], rule_parts[1], rule_parts[2], rule_parts[3]);
            
            // Calculate real lengths without color codes for padding
            char plain_fp[64], plain_rule[64];
            snprintf(plain_fp, sizeof(plain_fp), "%s:%s:%s:%s", 
                    fp_parts[0], fp_parts[1], fp_parts[2], fp_parts[3]);
            snprintf(plain_rule, sizeof(plain_rule), "%s:%s:%s:%s", 
                    rule_parts[0], rule_parts[1], rule_parts[2], rule_parts[3]);
                    
            // Print row with each column properly sized
            printf("| %-*d | ", ID_WIDTH-2, i+1);
            
            // Print fp column with proper padding
            print_padded_colored(colored_fp, FP_WIDTH - 2);
            
            printf(" | ");
            
            // Print rule column with proper padding
            print_padded_colored(colored_rule, RULE_WIDTH - 2);
            
            // Print hits and time with standard formatting
            printf(" | %-*llu | %-*s |\n", 
                   HITS_WIDTH-2, (unsigned long long)fingerprints[i].stats.count,
                   TIME_WIDTH-2, short_time_str);
        }
        
        // Print table footer
        printf("+%.*s+%.*s+%.*s+%.*s+%.*s+\n", 
               ID_WIDTH, "---------------------", 
               FP_WIDTH, "-------------------------------------------", 
               RULE_WIDTH, "-------------------------------------------", 
               HITS_WIDTH, "----------------", 
               TIME_WIDTH, "-------------------");
        
        // Add a separator between IPs
        if (ip_idx < ip_count - 1) {
            printf("\n");
        }
    }
    
    if (count > 10 * 5) {
        printf("\nShowing up to 10 IPs with up to 5 fingerprints each. Use --clear to reset.\n");
    }
    
    // For continuous mode, flush stdout
    if (continuous) {
        fflush(stdout);     // Ensure output is displayed immediately
    }
    
    if (using_multi_map) {
        close(multi_fp_map);
    }
}

/**
 * Check if two fingerprints match (ignoring action field)
 */
static bool fingerprints_match(const struct tcp_fingerprint *a, const struct tcp_fingerprint *b)
{
    // Compare basic fields
    if (a->window_size != b->window_size ||
        a->mss != b->mss ||
        a->window_scale != b->window_scale ||
        a->options_kind != b->options_kind ||
        a->fields_to_check != b->fields_to_check ||
        a->sequence_len != b->sequence_len) {
        return false;
    }
    
    // For complex sequences, compare the option sequences
    if (a->sequence_len > 0) {
        for (int i = 0; i < a->sequence_len; i++) {
            if (a->options_sequence[i] != b->options_sequence[i]) {
                return false;
            }
        }
    }
    
    // All fields match
    return true;
}

/**
 * Add a fingerprint to the filter
 */
static int add_fingerprint(int fp_map, int config_map, const char *pattern, uint8_t action)
{
    // Get current config
    uint32_t key = 0;
    struct config cfg;
    if (bpf_map_lookup_elem(config_map, &key, &cfg) != 0) {
        fprintf(stderr, "Failed to read configuration\n");
        return -1;
    }
    
    // Check if we have space
    if (cfg.fingerprint_count >= 64) {
        fprintf(stderr, "Maximum number of fingerprints (64) reached\n");
        return -1;
    }
    
    // Parse fingerprint
    struct tcp_fingerprint fp;
    if (parse_fingerprint(pattern, action, &fp) != 0) {
        fprintf(stderr, "Failed to parse fingerprint pattern: %s\n", pattern);
        return -1;
    }
    
    // Check for duplicates
    for (int i = 0; i < cfg.fingerprint_count; i++) {
        uint32_t idx = i;
        struct tcp_fingerprint existing_fp;
        
        if (bpf_map_lookup_elem(fp_map, &idx, &existing_fp) == 0) {
            if (fingerprints_match(&fp, &existing_fp)) {
                if (existing_fp.action == fp.action) {
                    if (debug) {
                        printf("Duplicate fingerprint found at index %d, not adding again\n", i);
                    }
                    return i;  // Return existing index
                } else {
                    // Same pattern but different action - update the action
                    existing_fp.action = fp.action;
                    if (bpf_map_update_elem(fp_map, &idx, &existing_fp, BPF_ANY) != 0) {
                        fprintf(stderr, "Failed to update fingerprint action: %s\n", strerror(errno));
                        return -1;
                    }
                    if (debug) {
                        printf("Updated action for existing fingerprint at index %d\n", i);
                    }
                    return i;  // Return updated index
                }
            }
        }
    }
    
    // Add to map as a new fingerprint
    uint32_t idx = cfg.fingerprint_count;
    if (bpf_map_update_elem(fp_map, &idx, &fp, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to add fingerprint: %s\n", strerror(errno));
        return -1;
    }
    
    // Update count
    cfg.fingerprint_count++;
    if (bpf_map_update_elem(config_map, &key, &cfg, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to update configuration: %s\n", strerror(errno));
        return -1;
    }
    
    return idx;
}

/**
 * Clear all fingerprints
 */
/**
 * Remove a specific fingerprint by ID
 */
static int remove_fingerprint(int fp_map, int config_map, int id)
{
    // Get config
    uint32_t key = 0;
    struct config cfg;
    
    if (bpf_map_lookup_elem(config_map, &key, &cfg) != 0) {
        fprintf(stderr, "Failed to get configuration\n");
        return -1;
    }
    
    // Check if ID is valid
    if (id >= cfg.fingerprint_count) {
        fprintf(stderr, "Invalid fingerprint ID: %d (max: %d)\n", id, cfg.fingerprint_count - 1);
        return -1;
    }
    
    // Get the fingerprint to display what we're removing
    uint32_t fp_key = id;
    struct tcp_fingerprint fp;
    if (bpf_map_lookup_elem(fp_map, &fp_key, &fp) != 0) {
        fprintf(stderr, "Failed to retrieve fingerprint with ID %d\n", id);
        return -1;
    }
    
    // First, try to clear any stats for this specific fingerprint ID
    // Move this BEFORE shifting the fingerprints to avoid race conditions
    char multi_fingerprint_path[256];
    snprintf(multi_fingerprint_path, sizeof(multi_fingerprint_path), "%s/multi_fingerprint_ips", 
             "/sys/fs/bpf");
    int multi_fp_map = bpf_obj_get(multi_fingerprint_path);
    
    if (multi_fp_map >= 0) {
        // Try to clear stats for all IPs with this fingerprint ID
        struct ip_fp_key key, next_key;
        memset(&key, 0, sizeof(key));
        
        // Clear stats for the fingerprint ID being removed
        while (bpf_map_get_next_key(multi_fp_map, &key, &next_key) == 0) {
            if (next_key.fingerprint_id == id) {
                // Delete the stat entry for this fingerprint ID
                bpf_map_delete_elem(multi_fp_map, &next_key);
            }
            key = next_key;
        }
        
        // Also clear stats for all fingerprints that will be shifted
        for (int shift_id = id + 1; shift_id < cfg.fingerprint_count; shift_id++) {
            memset(&key, 0, sizeof(key));
            
            while (bpf_map_get_next_key(multi_fp_map, &key, &next_key) == 0) {
                if (next_key.fingerprint_id == shift_id) {
                    // Delete stats for fingerprints that will be shifted
                    bpf_map_delete_elem(multi_fp_map, &next_key);
                }
                key = next_key;
            }
        }
        
        close(multi_fp_map);
    }
    
    // Format the fingerprint for display
    char pattern[64];
    format_muonfp(&fp, pattern, sizeof(pattern));
    
    // Since BPF array map doesn't support delete, we need to shift all 
    // fingerprints after this one up one position
    
    // First, read all fingerprints that need to be shifted into a temporary buffer
    struct tcp_fingerprint shifted_fps[64]; // Max is 64 fingerprints
    int shift_count = 0;
    
    // Read all fingerprints after the one being deleted
    for (int i = id + 1; i < cfg.fingerprint_count; i++) {
        uint32_t fp_idx = i;
        
        if (bpf_map_lookup_elem(fp_map, &fp_idx, &shifted_fps[shift_count]) != 0) {
            fprintf(stderr, "Failed to read fingerprint %d\n", i);
            return -1;
        }
        shift_count++;
    }
    
    // Now write them back, each shifted one position up
    for (int i = 0; i < shift_count; i++) {
        uint32_t write_idx = id + i; // Start from the position of the deleted fingerprint
        
        if (bpf_map_update_elem(fp_map, &write_idx, &shifted_fps[i], BPF_ANY) != 0) {
            fprintf(stderr, "Failed to update fingerprint %d\n", write_idx);
            return -1;
        }
    }
    
    // "Delete" the last position by writing zeros or removing it if possible
    uint32_t last_key = cfg.fingerprint_count - 1;
    struct tcp_fingerprint empty_fp;
    memset(&empty_fp, 0, sizeof(empty_fp));
    
    if (bpf_map_update_elem(fp_map, &last_key, &empty_fp, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to update last fingerprint slot\n");
        return -1;
    }
    
    // Decrement counter
    cfg.fingerprint_count--;
    
    // Update config
    if (bpf_map_update_elem(config_map, &key, &cfg, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to update configuration\n");
        return -1;
    }
    
    return 0;
}

static int clear_fingerprints(int fp_map, int config_map, int ip_map)
{
    // Reset config
    uint32_t key = 0;
    struct config cfg;
    if (bpf_map_lookup_elem(config_map, &key, &cfg) != 0) {
        fprintf(stderr, "Failed to read configuration\n");
        return -1;
    }
    
    // Keep default action but clear count
    cfg.fingerprint_count = 0;
    cfg.total_matches = 0;
    
    if (bpf_map_update_elem(config_map, &key, &cfg, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to update configuration: %s\n", strerror(errno));
        return -1;
    }
    
    // Clear legacy IP map
    key = 0;
    uint32_t next_key;
    while (bpf_map_get_next_key(ip_map, &key, &next_key) == 0) {
        bpf_map_delete_elem(ip_map, &next_key);
        key = next_key;
    }
    
    // Also clear the multi-fingerprint map if available
    char multi_fingerprint_path[256];
    snprintf(multi_fingerprint_path, sizeof(multi_fingerprint_path), "%s/multi_fingerprint_ips", 
             "/sys/fs/bpf");
    
    int multi_fp_map = bpf_obj_get(multi_fingerprint_path);
    if (multi_fp_map >= 0) {
        // Clear multi-fingerprint map
        struct ip_fp_key multi_key = {0};
        struct ip_fp_key next_multi_key;
        
        while (bpf_map_get_next_key(multi_fp_map, &multi_key, &next_multi_key) == 0) {
            bpf_map_delete_elem(multi_fp_map, &next_multi_key);
            multi_key = next_multi_key;
        }
        
        close(multi_fp_map);
    }
    
    return 0;
}

/**
 * Check if XDP program is loaded on interface
 */
static int check_xdp_program(int ifindex, __u32 *prog_id)
{
    int err = bpf_xdp_query_id(ifindex, 0, prog_id);
    if (err && debug)
        fprintf(stderr, "Failed to query XDP program: %s\n", strerror(-err));
    return err;
}

/**
 * Attach XDP program to interface
 */
static int attach_xdp_program(int ifindex, int prog_fd)
{
    __u32 curr_prog_id = 0;
    int err = check_xdp_program(ifindex, &curr_prog_id);
    if (err) {
        fprintf(stderr, "Failed to check existing XDP program: %s\n", strerror(-err));
        return err;
    }

    if (curr_prog_id != 0) {
        fprintf(stderr, "Interface already has an XDP program attached (prog_id: %u)\n", curr_prog_id);
        return -EEXIST;
    }

    // Try to load in DRV mode first (native), then SKB mode (generic) if that fails
    err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_DRV_MODE, NULL);
    if (err) {
        fprintf(stderr, "Failed to attach in DRV mode, trying generic SKB mode: %s\n", strerror(-err));
        
        // Try SKB mode as fallback
        err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL);
        if (err) {
            fprintf(stderr, "Failed to attach XDP program in SKB mode: %s\n", strerror(-err));
            return err;
        }
        printf("Successfully attached in SKB mode (slower but more compatible)\n");
    } else {
        printf("Successfully attached in DRV mode (best performance)\n");
    }

    return 0;
}

/**
 * Detach XDP program from interface
 */
static int detach_xdp_program(int ifindex)
{
    __u32 curr_prog_id = 0;
    int err = check_xdp_program(ifindex, &curr_prog_id);
    if (err) {
        fprintf(stderr, "Failed to check XDP program: %s\n", strerror(-err));
        return err;
    }

    if (curr_prog_id == 0) {
        if (debug)
            printf("No XDP program found on interface\n");
        return 0;
    }

    // Try all detachment methods to ensure the program is fully removed
    
    // First try to detach using DRV mode
    err = bpf_xdp_detach(ifindex, XDP_FLAGS_DRV_MODE, NULL);
    
    // Try SKB mode regardless of previous result
    int err2 = bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
    
    // Finally, try with no flags (force detach) regardless of previous results
    int err3 = bpf_xdp_detach(ifindex, 0, NULL);
    
    // Check if any method succeeded
    if (err && err2 && err3) {
        fprintf(stderr, "Failed to detach XDP program with all methods\n");
        return err; // Return the first error code
    }
    
    // Verify removal
    __u32 verify_prog_id = 0;
    err = check_xdp_program(ifindex, &verify_prog_id);
    if (err == 0 && verify_prog_id != 0) {
        fprintf(stderr, "Warning: XDP program still attached (prog_id: %u) after unload attempt\n", verify_prog_id);
    }

    return 0;
}

/**
 * Main program entry point
 */
int main(int argc, char **argv)
{
    int opt;
    bool continuous = false;
    const char *default_action = NULL;
    
    // Object file path for custom BPF program
    const char *custom_obj_path = NULL;
    
    struct option long_options[] = {
        {"debug", no_argument, 0, 'd'},
        {"continuous", no_argument, 0, 'c'},
        {"default-action", required_argument, 0, 'a'},
        {"help", no_argument, 0, 'h'},
        {"obj", required_argument, 0, 'o'},
        {0, 0, 0, 0}
    };
    
    // Parse options
    while ((opt = getopt_long(argc, argv, "ca:dho:", long_options, NULL)) != -1) {
        switch (opt) {
        case 'd':
            debug = 1;
            break;
        case 'c':
            continuous = true;
            break;
        case 'a':
            default_action = optarg;
            break;
        case 'o':
            custom_obj_path = optarg;
            break;
        case 'h':
            print_usage(argv[0]);
            return 0;
        default:
            print_usage(argv[0]);
            return 1;
        }
    }
    
    // Check arguments
    if (optind + 2 > argc) {
        print_usage(argv[0]);
        return 1;
    }
    
    // Get interface and command
    char *interface = argv[optind];
    char *command = argv[optind + 1];
    
    // Get interface index
    int ifindex = if_nametoindex(interface);
    if (!ifindex) {
        fprintf(stderr, "Invalid interface: %s\n", interface);
        return 1;
    }
    
    // Setup signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    libbpf_set_print(libbpf_print_fn);
    
    // Define map paths
    char blocked_ips_path[256];
    char fingerprints_path[256];
    char config_path[256];
    
    snprintf(blocked_ips_path, sizeof(blocked_ips_path), "%s/blocked_ips", MAP_PATH_BASE);
    snprintf(fingerprints_path, sizeof(fingerprints_path), "%s/tcp_fingerprints", MAP_PATH_BASE);
    snprintf(config_path, sizeof(config_path), "%s/config_map", MAP_PATH_BASE);
    
    // Execute command
    if (strcmp(command, "load") == 0) {
        // Remove any existing pinned maps
        unlink(blocked_ips_path);
        unlink(fingerprints_path);
        unlink(config_path);
        
        // If a custom object file was specified, use that
        struct bpf_object *obj = NULL;
        const char *obj_path = NULL;
        
        if (custom_obj_path) {
            // Use the user-specified BPF object file
            if (access(custom_obj_path, R_OK) == 0) {
                obj_path = custom_obj_path;
            } else {
                fprintf(stderr, "Cannot access custom BPF object file: %s\n", custom_obj_path);
                return 1;
            }
        } else {
            // Try to find the BPF object file in standard locations
            const char *obj_paths[] = {
                "build/xdp_filter.o",
                "./xdp_filter.o",
                "../build/xdp_filter.o",
                "/usr/local/bin/xdp_filter.o",
                NULL
            };
            
            for (int i = 0; obj_paths[i] != NULL; i++) {
                if (access(obj_paths[i], R_OK) == 0) {
                    obj_path = obj_paths[i];
                    break;
                }
            }
        }
        
        if (!obj_path) {
            fprintf(stderr, "Failed to find XDP object file. Make sure to compile it first.\n");
            return 1;
        }
        
        if (debug)
            printf("Loading BPF object from %s\n", obj_path);
        
        // Load the BPF object
        obj = bpf_object__open_file(obj_path, NULL);
        if (libbpf_get_error(obj)) {
            fprintf(stderr, "Failed to open BPF object file: %s\n", strerror(errno));
            return 1;
        }
        
        // Load into kernel
        int err = bpf_object__load(obj);
        if (err) {
            fprintf(stderr, "Failed to load BPF object: %s (error code: %d)\n", 
                    strerror(abs(err)), err);
            
            // Check for common issues
            if (err == -13) { // EACCES
                fprintf(stderr, "Permission denied. Try:\n");
                fprintf(stderr, "1. Running with sudo\n");
                fprintf(stderr, "2. Setting kernel.unprivileged_bpf_disabled=0 with sysctl\n");
                fprintf(stderr, "3. Check if /sys/fs/bpf is mounted with: mount | grep bpf\n");
            } else if (err == -22) { // EINVAL
                fprintf(stderr, "Invalid argument. This could be due to:\n");
                fprintf(stderr, "1. Kernel version mismatch\n");
                fprintf(stderr, "2. Missing BTF information\n");
                fprintf(stderr, "3. Try running: sudo ./check_btf.sh\n");
            }
            
            bpf_object__close(obj);
            return 1;
        }
        
        // Find program
        struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_scanner_filter");
        if (!prog) {
            fprintf(stderr, "Failed to find XDP program\n");
            bpf_object__close(obj);
            return 1;
        }
        
        // Set default configuration
        struct bpf_map *config_map = bpf_object__find_map_by_name(obj, "config_map");
        if (!config_map) {
            fprintf(stderr, "Failed to find config map\n");
            bpf_object__close(obj);
            return 1;
        }
        
        int config_fd = bpf_map__fd(config_map);
        struct config cfg = {
            .fingerprint_count = 0,
            .default_action = XDP_PASS,
            .total_matches = 0
        };
        
        // Apply default action if specified
        if (default_action) {
            cfg.default_action = string_to_action(default_action);
        }
        
        uint32_t key = 0;
        if (bpf_map_update_elem(config_fd, &key, &cfg, BPF_ANY)) {
            fprintf(stderr, "Failed to initialize configuration\n");
            bpf_object__close(obj);
            return 1;
        }
        
        // Attach to interface
        if (attach_xdp_program(ifindex, bpf_program__fd(prog)) != 0) {
            fprintf(stderr, "Failed to attach XDP program\n");
            bpf_object__close(obj);
            return 1;
        }
        
        printf("Successfully loaded and attached TCP fingerprint filter to %s\n", interface);
        printf("Default action: %s\n", action_to_string(cfg.default_action));
        bpf_object__close(obj);
    }
    else if (strcmp(command, "unload") == 0) {
        if (detach_xdp_program(ifindex) != 0) {
            fprintf(stderr, "Failed to detach XDP program\n");
            return 1;
        }
        
        // Remove pinned maps
        unlink(blocked_ips_path);
        unlink(fingerprints_path);
        unlink(config_path);
        
        printf("Successfully unloaded TCP fingerprint filter from %s\n", interface);
    }
    else if (strcmp(command, "show") == 0) {
        int ip_map = bpf_obj_get(blocked_ips_path);
        int fp_map = bpf_obj_get(fingerprints_path);
        int config_map = bpf_obj_get(config_path);
        
        if (ip_map < 0 || fp_map < 0 || config_map < 0) {
            fprintf(stderr, "Failed to access maps. Is the filter loaded?\n");
            return 1;
        }
        
        if (continuous) {
            while (running) {
                list_ips(ip_map, fp_map, config_map, true);
                sleep(1);
            }
        } else {
            list_ips(ip_map, fp_map, config_map, false);
        }
        
        close(ip_map);
        close(fp_map);
        close(config_map);
    }
    else if (strcmp(command, "list") == 0) {
        int fp_map = bpf_obj_get(fingerprints_path);
        int config_map = bpf_obj_get(config_path);
        
        if (fp_map < 0 || config_map < 0) {
            fprintf(stderr, "Failed to access maps. Is the filter loaded?\n");
            return 1;
        }
        
        list_fingerprints(fp_map, config_map);
        
        close(fp_map);
        close(config_map);
    }
    else if (strcmp(command, "add") == 0) {
        if (optind + 4 > argc) {
            fprintf(stderr, "Usage: %s <interface> add <pattern> <action>\n", argv[0]);
            return 1;
        }
        
        char *pattern = argv[optind + 2];
        char *action_str = argv[optind + 3];
        uint8_t action = string_to_action(action_str);
        
        int fp_map = bpf_obj_get(fingerprints_path);
        int config_map = bpf_obj_get(config_path);
        
        if (fp_map < 0 || config_map < 0) {
            fprintf(stderr, "Failed to access maps. Is the filter loaded?\n");
            return 1;
        }
        
        int id = add_fingerprint(fp_map, config_map, pattern, action);
        if (id >= 0) {
            printf("Added fingerprint with ID %d: %s (%s)\n", id, pattern, action_str);
        }
        
        close(fp_map);
        close(config_map);
    }
    else if (strcmp(command, "remove") == 0) {
        if (optind + 3 > argc) {
            fprintf(stderr, "Usage: %s <interface> remove <id>\n", argv[0]);
            return 1;
        }
        
        // Validate ID is a numeric value
        char *id_str = argv[optind + 2];
        char *endptr;
        long id_value = strtol(id_str, &endptr, 10);
        
        // Check for invalid input (non-numeric, out of range)
        if (*endptr != '\0' || id_value < 0 || id_value > INT_MAX) {
            fprintf(stderr, "Invalid fingerprint ID: '%s'. Must be a non-negative integer.\n", id_str);
            return 1;
        }
        
        int id = (int)id_value;
        
        int fp_map = bpf_obj_get(fingerprints_path);
        int config_map = bpf_obj_get(config_path);
        
        if (fp_map < 0 || config_map < 0) {
            fprintf(stderr, "Failed to access maps. Is the filter loaded?\n");
            return 1;
        }
        
        // Get configuration to validate ID is in range
        uint32_t cfg_key = 0;
        struct config cfg;
        if (bpf_map_lookup_elem(config_map, &cfg_key, &cfg) != 0) {
            fprintf(stderr, "Failed to read configuration\n");
            close(fp_map);
            close(config_map);
            return 1;
        }
        
        // Check if ID is in valid range
        if (id >= cfg.fingerprint_count) {
            fprintf(stderr, "Invalid fingerprint ID: %d (max: %d)\n", id, 
                    cfg.fingerprint_count > 0 ? cfg.fingerprint_count - 1 : 0);
            close(fp_map);
            close(config_map);
            return 1;
        }
        
        // Get the fingerprint to display what we're removing
        uint32_t fp_key = id;
        struct tcp_fingerprint fp;
        char pattern[64] = "unknown";
        
        if (bpf_map_lookup_elem(fp_map, &fp_key, &fp) == 0) {
            format_muonfp(&fp, pattern, sizeof(pattern));
        }
        
        if (remove_fingerprint(fp_map, config_map, id) == 0) {
            printf("Removed fingerprint with ID %d: %s (%s)\n", id, pattern, 
                   action_to_string(fp.action));
        }
        
        close(fp_map);
        close(config_map);
    }
    else if (strcmp(command, "clear") == 0) {
        int fp_map = bpf_obj_get(fingerprints_path);
        int config_map = bpf_obj_get(config_path);
        int ip_map = bpf_obj_get(blocked_ips_path);
        
        if (fp_map < 0 || config_map < 0 || ip_map < 0) {
            fprintf(stderr, "Failed to access maps. Is the filter loaded?\n");
            return 1;
        }
        
        if (clear_fingerprints(fp_map, config_map, ip_map) == 0) {
            printf("Cleared all fingerprints and matched IPs\n");
        }
        
        close(fp_map);
        close(config_map);
        close(ip_map);
    }
    else {
        fprintf(stderr, "Unknown command: %s\n", command);
        print_usage(argv[0]);
        return 1;
    }
    
    return 0;
}