/* SPDX-License-Identifier: MIT */
/*
 * log.h - Logging system for Phantom.
 *
 * Provides timestamped log messages with severity levels.
 * Messages are printed to stderr.
 *
 * Usage:
 *   LOG_INFO("Phantom loaded successfully");
 *   LOG_ERROR("Failed to open file: %s", strerror(errno));
 *   LOG_WARN("Only %d slots remaining", count);
 */

#ifndef __PHANTOM_LOG_H
#define __PHANTOM_LOG_H

#include <stdio.h>
#include <stdarg.h>
#include <time.h>

/*
 * enum log_level - Log message severity levels.
 *
 * Messages below the current threshold are suppressed.
 * Levels (least to most severe):
 *   LOG_DEBUG (0) - Verbose diagnostic output
 *   LOG_INFO  (1) - Normal operational messages
 *   LOG_WARN  (2) - Unexpected but non-fatal conditions
 *   LOG_ERROR (3) - Failure conditions
 */
enum log_level {
    LOG_DEBUG = 0,
    LOG_INFO = 1,
    LOG_WARN = 2,
    LOG_ERROR = 3,
};

/*
 * log_set_level - Set minimum severity threshold for output.
 *
 * Only messages at or above this level are printed.
 */
void log_set_level(enum log_level level);

/*
 * log_msg - Print a formatted log message.
 *
 * Checks severity against current threshold, prepends timestamp
 * and level name, then writes to stderr.
 *
 * Parameters:
 *   level - Message severity
 *   fmt   - printf-style format string
 *   ...   - Format arguments
 */
void log_msg(enum log_level level, const char *fmt, ...);

/*
 * Convenience macros - LOG_INFO(...) expands to log_msg(LOG_INFO, ...).
 */
#define LOG_DEBUG(fmt, ...) log_msg(LOG_DEBUG, fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)  log_msg(LOG_INFO, fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  log_msg(LOG_WARN, fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) log_msg(LOG_ERROR, fmt, ##__VA_ARGS__)

#endif /* __PHANTOM_LOG_H */
