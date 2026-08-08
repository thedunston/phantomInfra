// SPDX-License-Identifier: MIT
/*
 * log.c - Timestamped stderr logging for Phantom.
 *
 * LOG_INFO / LOG_ERROR and related macros call log_msg(). Output format:
 *   [2025-01-15 14:30:22] [INFO ] hello
 *
 * Messages go to stderr so they stay separate from stdout pipes.
 * Messages below current_level are discarded.
 */

#include "log.h"
#include <stdio.h>
#include <stdarg.h>
#include <time.h>

/*
 * current_level - Minimum severity that gets printed.
 *
 * With LOG_WARN, LOG_DEBUG and LOG_INFO are discarded; LOG_WARN and
 * LOG_ERROR still print. File-local static.
 */
static enum log_level current_level = LOG_INFO;

/*
 * log_set_level - Set the minimum severity for message output.
 *
 * Example:
 *   log_set_level(LOG_DEBUG);  // all levels
 *   log_set_level(LOG_INFO);   // default
 *   log_set_level(LOG_ERROR);  // errors only
 */
void log_set_level(enum log_level level)
{
    current_level = level;
}

/*
 * log_msg - Format and print a timestamped log message to stderr.
 *
 * Skips messages below current_level. Formats time as YYYY-MM-DD HH:MM:SS,
 * then prints "[time] [LEVEL] " and the printf-style message.
 *
 * Parameters:
 *   level - LOG_DEBUG, LOG_INFO, LOG_WARN, or LOG_ERROR
 *   fmt   - printf-style format string
 *   ...   - format arguments
 */
void log_msg(enum log_level level, const char *fmt, ...)
{
    /* Drop messages below the configured threshold. */
    if (level < current_level)
        return;

    /* Fixed-width level labels keep columns aligned. */
    const char *level_str;
    switch (level) {
    case LOG_DEBUG: level_str = "DEBUG"; break;
    case LOG_INFO:  level_str = "INFO "; break;
    case LOG_WARN:  level_str = "WARN "; break;
    case LOG_ERROR: level_str = "ERROR"; break;
    default:        level_str = "?????"; break;
    }

    /* localtime + strftime -> "YYYY-MM-DD HH:MM:SS". */
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char timebuf[64];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm);

    /* stderr: unbuffered, separate from stdout pipes. */
    fprintf(stderr, "[%s] [%s] ", timebuf, level_str);

    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);

    fprintf(stderr, "\n");
}
