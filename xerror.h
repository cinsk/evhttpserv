#ifndef XERROR_H__
#define XERROR_H__

#ifndef __GNUC__
#error GCC is required to use this header
#endif

/*
 * This header provides simple error message printing functions,
 * which is almost duplicated version of error in GLIBC.
 *
 * Works in Linux and MacOS.
 */

#include <stdarg.h>
#include <stdio.h>

/* This indirect using of extern "C" { ... } makes Emacs happy */
#ifndef BEGIN_C_DECLS
# ifdef __cplusplus
#  define BEGIN_C_DECLS extern "C" {
#  define END_C_DECLS   }
# else
#  define BEGIN_C_DECLS
#  define END_C_DECLS
# endif
#endif /* BEGIN_C_DECLS */

BEGIN_C_DECLS

extern const char *xbacktrace_executable;

/*
 * xerror module now support ignore file (".xerrignore").
 *
 * If the source filename that calls xdebug() is matched to the
 * patterns in ".xerrignore", then xdebug() will not print the message
 * but simply return.
 *
 * xerror_init() will search ".xerrignore" file in the current working
 * directory, and tries to find the file until it reaches the root
 * directory (like how GDB does for ".gdbinit").
 *
 * The contents of .xerrignore is very simple.  Empty lines and lines
 * with first character '#' are ignored.  Each line may hold one
 * wildcard pattern.  See fnmatch(3) for more.
 */

/*
 * Environment Variables:
 *
 * - XBACKTRACE: if not defined, xbacktrace_on_signals() will do nothing.
 * - XBACKTRACE_NOGDB: if defined, xbacktrace_on_signals will not use GDB(1).
 * - XBACKTRACE_FILE: This is the filename template for the backtrace info.
 *                    The actual filename will be $XBACKTRACE_FILE.PID,
 *                    where PID is the pid of the process.
 * - XERROR_IGNORES: filename for the ignore patterns.
 */

/*
 * Recommended way to initialize xerror module.
 *
 * PROGRAM_NAME will override the name of the program if non-zero.
 * IGNORE_SEARCH_DIR will override the default directory to find ".xerrignore".
 *
 */
extern int xerror_init(const char *program_name, const char *ignore_search_dir);

extern int xthread_set_name(const char *name, ...);
extern const char *xthread_get_name(char *buf, size_t sz);

/*
 * xerror() is the same as error() in GLIBC.
 */
extern void xerror(int status, int code, const char *format, ...)
  __attribute__((format (printf, 3, 4)));

/*
 * xdebug(...) is like xerror(0, ...), except that it embeds the
 * caller's filename and line number in the messages.  The output will
 * not be generated if the application defined 'debug_mode' to zero.
 *
 * By default, 'debug_mode' is set to zero.
 */
#define xdebug(code, fmt, ...)                                          \
    xdebug_((code), ("%s:%d: " fmt), __FILE__, __LINE__, ## __VA_ARGS__)

/*
 * Return nonzero if 'debug_mode' is nonzero.
 */
extern int xifdebug(void);

extern void xdebug_(int code, const char *format, ...)
  __attribute__((format (printf, 2, 3)));

extern void xmessage(int progname, int code, int ignore, int show_tid,
                     const char *format, va_list ap);

/*
 * By default, all x*() functions will send the output to STDERR.
 * You can override the output stream using xerror_redirect().
 *
 * This function returns the previous output stream if any.
 *
 * Note that if you didn't set explicitly the output stream to STDERR,
 * this function will return NULL.  This may be helpful if you want to
 * close the previous output stream except STDERR.
 *
 * It is recommended that you call fopen() with "a" open mode for it's
 * second argument.
 */
extern FILE *xerror_redirect(FILE *fp);

/*
 * Register one or more signals to generate backtrace if the program
 * receives signals.  Note that the last argument should be zero.
 */
extern int xbacktrace_on_signals(int signo, ...);

END_C_DECLS

#endif  /* XERROR_H__ */
