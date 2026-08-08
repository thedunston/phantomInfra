/* SPDX-License-Identifier: MIT */
/*
 * phantom_limits.h - Shared buffer size limits and feature constants.
 *
 * Included by both phantom.h (BPF + userspace) and config.h (userspace only)
 * to avoid duplicate #define definitions.
 *
 * These constants have no type dependencies — pure integer literals.
 */

#ifndef __PHANTOM_LIMITS_H
#define __PHANTOM_LIMITS_H

/* Process names (Linux TASK_COMM_LEN) */
#define TASK_COMM_LEN 16

/* File and path limits */
#define MAX_PATH_LEN 256
#define MAX_FILENAME_LEN 64
#define MAX_PREFIX_LEN 32
/* Exe path prefixes for process hide-prefix (LPM trie key data) */
#define MAX_PROC_PATH_PREFIX_LEN 64
#define MAX_HIDDEN_PROC_PATH_PREFIXES 32

/* Hide rule capacity limits */
#define MAX_HIDDEN_PIDS 128
#define MAX_HIDDEN_FILES 64
#define MAX_HIDDEN_PORTS 32
#define MAX_HIDDEN_PREFIXES 32
#define MAX_HIDDEN_EXEC_NAMES 64
#define MAX_HIDDEN_IFACES 32
#define MAX_HIDDEN_IPS 64

/* File content filtering limits */
#define MAX_FILE_FILTERS 32
#define MAX_FILE_FILTER_PATH 128
#define MAX_FILE_FILTER_SEARCH 64
#define MAX_FILE_FILTER_REPLACE 64
#define MAX_FILE_FILTER_EXEMPTS 32

/* File filter modes */
#define FILE_FILTER_MODE_HIDE 0
#define FILE_FILTER_MODE_REPLACE 1

#endif /* __PHANTOM_LIMITS_H */
