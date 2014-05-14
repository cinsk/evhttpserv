/*
 * error logging module with backtrace feature
 * Copyright (C) 2014  Seong-Kook Shin <cinsky@gmail.com>
 * DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
 * Version 2, December 2004
 *
 * Copyright (C) 2014 Seong-Kook Shin <cinsky@gmail.com>
 *
 * Everyone is permitted to copy and distribute verbatim or modified
 * copies of this license document, and changing it is allowed as long
 * as the name is changed.
 *
 *            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
 *   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
 *
 *  0. You just DO WHAT THE FUCK YOU WANT TO.
 *
 * This program is free software. It comes without any warranty, to the
 * extent permitted by applicable law. You can redistribute it and/or
 * modify it under the terms of the Do What The Fuck You Want To Public
 * License, Version 2, as published by Sam Hocevar. See
 * http://www.wtfpl.net/ for more details.
 */

#define _GNU_SOURCE     1
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <limits.h>

#include <stdint.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <fnmatch.h>

#ifdef _PTHREAD
#include <pthread.h>
#endif

#ifndef NO_MCONTEXT
# ifdef __APPLE__
/* MacOSX deprecates <ucontext.h> */
#  include <sys/ucontext.h>
# else
#  include <ucontext.h>
# endif
#endif  /* NO_MCONTEXT */

#include <unistd.h>
#include <signal.h>
#include <execinfo.h>

#ifndef __GLIBC__
/* In GLIBC, <string.h> will provide better basename(3). */
#include <libgen.h>
#endif

#ifdef _PTHREAD
#include <pthread.h>
#endif

#include "xerror.h"

#ifdef __APPLE__
#include <mach-o/dyld.h>
#include <libgen.h>
#include <limits.h>
#endif

#ifdef __linux__
#include <sys/syscall.h>
#endif

#define BACKTRACE_MAX   16
#define IGNORE_ENVNAME  "XERROR_IGNORES"
#define IGNORE_FILENAME ".xerrignore"

const char *xbacktrace_executable __attribute__((weak)) = "backtrace";

/* glibc compatible name */
const char *program_name __attribute__((weak)) = 0;

int debug_mode __attribute__((weak));
int backtrace_mode __attribute__((weak)) = 1;
int printtid_mode __attribute__((weak)) = 0;

static void set_program_name(void) __attribute__((constructor));

static FILE *xerror_stream = (FILE *)-1;
static int xerror_fd = -1;

#ifdef _PTHREAD
pthread_mutex_t xerror_mutex = PTHREAD_MUTEX_INITIALIZER;
#define LOCK()          pthread_mutex_lock(&xerror_mutex)
#define UNLOCK()        pthread_mutex_unlock(&xerror_mutex)
#else
#define LOCK()          ((void)0)
#define UNLOCK()        ((void)0)
#endif  /* _PTHREAD */

static int xerror_bt_filep = 0;
static char *xerror_bt_filename = 0;
static char *xerror_bt_command = 0;
static void bt_handler(int signo, siginfo_t *info, void *uctx_void);
static void bt_handler_gdb(int signo, siginfo_t *info, void *uctx_void);

static int get_tid(void);

static int ign_reserve(void);
static int ign_load(const char *basedir);
static int ign_load_file(const char *pathname);
static int ign_match(const char *src);
static void ign_free(void);

static void xerror_finalize(void) __attribute__((destructor));
static char *find_executable(const char *exe);


static __inline__ FILE *
xerror_redirect_unlocked(FILE *fp)
{
  FILE *old = xerror_stream;
  sigset_t set, oldset;

  assert(fp != NULL);

  {
    if (old == (FILE *)-1)
      old = NULL;
    else
      fflush(old);

    if (xerror_stream == fp) {
      return 0;
    }
  }

  fflush(fp);

  /* There could be a debate, whether removing internal buffer of FILE
   * stream is a good choice.  If the stream has buffer, then the
   * delay causes by all xerror() related functions will be
   * insignificant.  In the other hand, having internal buffer may
   * cause some logs will be lost in critial error situations. */
  setvbuf(fp, 0, _IONBF, 0);

  sigfillset(&set);
#ifdef _PTHREAD
  pthread_sigmask(SIG_BLOCK, &set, &oldset);
#else
  sigprocmask(SIG_BLOCK, &set, &oldset);
#endif

  /* Note for the maintainers:
   *
   * In a multi-threaded environment, you need to put extra care to
   * the race condition of the accessing either of 'xerror_stream' or
   * 'xerror_fd'.  During xerror_redirect(), other threads may call
   * xerror() related functions, and they will access these
   * variables.
   *
   * Currently, if there is a previous stream, I use
   * flockfile()/funlockfil() so that no one can interfere assigning
   * new value at 'xerror_stream'.  -- cinsk */

  xerror_stream = fp;
  xerror_fd = fileno(fp);

#ifdef _PTHREAD
  pthread_sigmask(SIG_SETMASK, &oldset, 0);
#else
  sigprocmask(SIG_SETMASK, &oldset, 0);
#endif

  if (old) {
    __sync_synchronize();       /* is this necessary? */
    funlockfile(old);
  }

  return old;
}


FILE *
xerror_redirect(FILE *fp)
{
  FILE *ret;
  LOCK();
  ret = xerror_redirect_unlocked(fp);
  UNLOCK();
  return ret;
}




#ifdef __APPLE__
static void
darwin_program_name(void)
{
  static char namebuf[PATH_MAX];
  uint32_t bufsize = PATH_MAX;
  int ret;

  ret = _NSGetExecutablePath(namebuf, &bufsize);
  if (ret == 0) {
    program_name = basename(namebuf);
  }
}
#endif  /* __APPLE__ */


static void
set_program_name(void)
{
#ifdef __APPLE__
  darwin_program_name();
#elif defined(__GLIBC__)
  program_name = basename(program_invocation_short_name);
#endif

}


int
xbacktrace_on_signals(int signo, ...)
{
  struct sigaction act;
  va_list ap;
  char *exe, *gdb;
#ifdef USE_ALTSTACK
  stack_t ss;
#endif
  char *file = getenv("XBACKTRACE_FILE");
  int ret = 0;

  if (getenv("XBACKTRACE") == 0)
    return 0;

  free(xerror_bt_filename);
  free(xerror_bt_command);

  if (file) {
    asprintf(&xerror_bt_filename, "%s.%d", file, (int)getpid());
    xerror_bt_filep = 1;
  }
  else
    asprintf(&xerror_bt_filename, "backtrace.%d", (int)getpid());

  asprintf(&xerror_bt_command, "backtrace -w -o %s %d",
           xerror_bt_filename, (int)getpid());

#ifdef USE_ALTSTACK
  /* Why uses SIGSTKSZ * 2? -- Don't know why, but segfault.c in glibc
   * uses it -- cinsk */
  ss.ss_sp = malloc(SIGSTKSZ * 2);
  ss.ss_size = SIGSTKSZ * 2;
  ss.ss_flags = 0;
  if (sigaltstack(&ss, NULL) == -1)
    xerror(0, errno, "can't register altstack");
#endif  /* USE_ALTSTACK */

  memset(&act, 0, sizeof(act));

  exe = find_executable(xbacktrace_executable);
  gdb = find_executable("gdb");

  if (exe && gdb && getenv("XBACKTRACE_NOGDB") == 0)
    act.sa_sigaction = bt_handler_gdb;
  else
    act.sa_sigaction = bt_handler;

  free(gdb);
  free(exe);

  sigemptyset(&act.sa_mask);
  act.sa_flags = SA_SIGINFO | SA_RESETHAND;
#ifdef USE_ALTSTACK
  act.sa_flags |= SA_ONSTACK;
#endif

  ret = sigaction(signo, &act, NULL);
  if (ret != 0) {
    xerror(0, errno, "can't register a handler for signal %d", signo);
    return -1;
  }

  va_start(ap, signo);
  while ((signo = (int)va_arg(ap, int)) != 0) {
    ret = sigaction(signo, &act, NULL);
    if (ret != 0) {
      xerror(0, errno, "can't register a handler for signal %d", signo);
      va_end(ap);
      return -1;
    }
  }
  va_end(ap);
  return 0;
}


void
xerror(int status, int code, const char *format, ...)
{
  va_list ap;

  va_start(ap, format);
  xmessage(!printtid_mode, code, 0, printtid_mode, format, ap);
  va_end(ap);

  if (!status)
    return;

  if (status > 0)
    exit(status);

  abort();
}


int
xifdebug()
{
  return debug_mode;
}


void
xdebug_(int code, const char *format, ...)
{
  va_list ap;

  if (!debug_mode)
    return;

  va_start(ap, format);
  xmessage(0, code, 1, printtid_mode, format, ap);
  va_end(ap);
}


void
xmessage(int progname, int code, int ignore, int show_tid,
         const char *format, va_list ap)
{
  char errbuf[BUFSIZ];
  int saved_errno = errno;
#ifdef _PTHREAD
  int cancel_state = PTHREAD_CANCEL_ENABLE;
#endif

  if (ignore) {
    va_list vcp;
    int pred;

    va_copy(vcp, ap);
    pred = ign_match((const char *)va_arg(vcp, const char *));
    va_end(vcp);

    if (pred)
      return;
  }

  LOCK();

#ifdef _PTHREAD
  pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);
#endif

  if (xerror_stream == (FILE *)-1) {
    if (stderr != NULL)
      xerror_redirect_unlocked(stderr);
    else
      goto fin;
  }

  if (!xerror_stream)
    return;

  fflush(stdout);
  fflush(xerror_stream);

  flockfile(xerror_stream);

  if (progname) {
    if (program_name)
      fprintf(xerror_stream, "%s: ", program_name);
  }
  else {
    if (show_tid) {
      const char *tname = xthread_get_name(errbuf, BUFSIZ);
      if (!tname || tname[0] == '\0')
        tname = "T";
      fprintf(xerror_stream, "%s-%u: ", tname, get_tid());
    }
  }

  vfprintf(xerror_stream, format, ap);

  if (code) {
#if defined(_GNU_SOURCE) && !defined(__APPLE__)
    fprintf(xerror_stream, ": (errno=%d) %s",
            code, strerror_r(code, errbuf, BUFSIZ));
#else
    /* We'll use XSI-compliant strerror_r() */
    errno = 0;
    if (strerror_r(code, errbuf, BUFSIZ) == 0)
      fprintf(xerror_stream, ": (errno=%d) %s", code, errbuf);
    else if (errno == ERANGE)
      fprintf(xerror_stream, ": [xerror] invalid error code");
    else
      fprintf(xerror_stream, ": [xerror] strerror_r(3) failed (errno=%d)",
              errno);
#endif  /* _GNU_SOURCE */
  }

  fputc('\n', xerror_stream);

  funlockfile(xerror_stream);
  errno = saved_errno;

 fin:
#ifdef _PTHREAD
  pthread_setcancelstate(cancel_state, NULL);
#endif

  UNLOCK();
}


static char *
long2str(char *buf, size_t bufsize, long l, int base)
{
  char *p = buf + bufsize - 1;
  int negative = 0;

  if (bufsize == 0)
    return 0;

  *p-- = '\0';

  do {
    long d = l % base;

    if (d < 0) {
      negative = 1;
      d = -d;
    }

    if (p < buf)
      return 0;
    *p-- = "0123456789ABCDEF"[d];
    l /= base;
  } while (l != 0);

  if (negative && base == 10) {
    if (p < buf)
      return 0;
    *p-- = '-';
  }

  return p + 1;
}


#define NUMBUF_MAX      32

#define WRITE_NUM(fd, num, base)        do {             \
  char nbuf[NUMBUF_MAX];                                 \
  char *n;                                               \
  n = long2str(nbuf, NUMBUF_MAX, (num), (base));         \
  if (n) write((fd), n, strlen(n));                      \
  } while (0)

#define WRITE_STR(fd, s)        write((fd), (s), strlen(s))

static void
bt_handler(int signo, siginfo_t *info, void *uctx_void)
{
  void *trace[BACKTRACE_MAX];
  int ret;
  int bt_fd;

  (void)uctx_void;

  if (!backtrace_mode)
    return;

  __sync_synchronize();

  bt_fd = open(xerror_bt_filename, O_WRONLY | O_APPEND | O_CREAT, 0644);
  if (bt_fd == -1) {
    bt_fd = xerror_fd;
    WRITE_STR(bt_fd, "Can't open the backtrace file, ");
    write(bt_fd, xerror_bt_filename, strlen(xerror_bt_filename));
    WRITE_STR(bt_fd, "\n");
  }

  {
#ifndef NO_MCONTEXT
# ifdef __APPLE__
    ucontext_t *uctx = (ucontext_t *)uctx_void;
    uint64_t pc = uctx->uc_mcontext->__ss.__rip;

    WRITE_STR(bt_fd, "Got signal (");
    WRITE_NUM(bt_fd, signo, 10);

    WRITE_STR(bt_fd, ") at address 0x");
    WRITE_NUM(bt_fd, (unsigned long)info->si_addr, 16);
    WRITE_STR(bt_fd, ", RIP=[0x");
    WRITE_NUM(bt_fd, pc, 16);
    WRITE_STR(bt_fd, "]\n");

# elif defined(REG_EIP) /* linux */
    ucontext_t *uctx = (ucontext_t *)uctx_void;
    greg_t pc = uctx->uc_mcontext.gregs[REG_EIP];

    WRITE_STR(bt_fd, "Got signal (");
    WRITE_NUM(bt_fd, signo, 10);

    WRITE_STR(bt_fd, ") at address 0x");
    WRITE_NUM(bt_fd, (unsigned long)info->si_addr, 16);
    WRITE_STR(bt_fd, ", EIP=[0x");
    WRITE_NUM(bt_fd, pc, 16);
    WRITE_STR(bt_fd, "]\n");

# elif defined(REG_RIP) /* linux */
    ucontext_t *uctx = (ucontext_t *)uctx_void;
    greg_t pc = uctx->uc_mcontext.gregs[REG_RIP];

    WRITE_STR(bt_fd, "Got signal (");
    WRITE_NUM(bt_fd, signo, 10);

    WRITE_STR(bt_fd, ") at address 0x");
    WRITE_NUM(bt_fd, (unsigned long)info->si_addr, 16);
    WRITE_STR(bt_fd, ", RIP=[0x");
    WRITE_NUM(bt_fd, pc, 16);
    WRITE_STR(bt_fd, "]\n");

# endif
#else

    WRITE_STR(bt_fd, "Got signal (");
    WRITE_NUM(bt_fd, signo, 10);

    WRITE_STR(bt_fd, ") at address 0x");
    WRITE_NUM(bt_fd, (unsigned long)info->si_addr, 16);
    WRITE_STR(bt_fd, "\n");

#endif  /* NO_MCONTEXT */
  }

  /* WARNING!
   *
   * None of functions that used below are async signal-safe.
   * Thus, this is not a portable code. -- cinsk
   */

  /*
   * TODO: adhere XBACKTRACE_FILE environment variable.
   */
  WRITE_STR(bt_fd, "\nBacktrace:\n");
  ret = backtrace(trace, BACKTRACE_MAX);
  /* TODO: error check on backtrace(3)? */

  // fflush(xerror_stream);

  if (!xerror_bt_filep)
    backtrace_symbols_fd(trace, ret, bt_fd);
  else {
    int fd;
    fd = open(xerror_bt_filename, O_CREAT | O_WRONLY, 0600);
    if (fd != -1) {
      backtrace_symbols_fd(trace, ret, fd);
      close(fd);
    }
  }
  // fflush(xerror_stream);

  /* http://tldp.org/LDP/abs/html/exitcodes.html */
  // _exit(128 + signo);

  {
    struct sigaction sa;

    sa.sa_handler = SIG_DFL;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(signo, &sa, NULL);
    raise(signo);
  }
}


static void
bt_handler_gdb(int signo, siginfo_t *info, void *uctx_void)
{
#if 0
  static char cmdbuf[LINE_MAX] = { 0, };
  static char cwd[PATH_MAX];

  char *file = getenv("XBACKTRACE_FILE");

  if (file)
    snprintf(cmdbuf, LINE_MAX - 1, "backtrace -w -o %s.%d %d",
             file, (int)getpid(), (int)getpid());
  else {
    if (getcwd(cwd, PATH_MAX) == 0)
      cwd[0] = '\0';

    if (getppid() == 1 || strcmp(cwd, "/") == 0) {
      if (access("/var/log", W_OK) == 0)
        snprintf(cmdbuf, LINE_MAX - 1, "backtrace -w -o /var/log/gdb.%d %d",
                 (int)getpid(), (int)getpid());
      else
        snprintf(cmdbuf, LINE_MAX - 1, "backtrace -w -o /tmp/gdb.%d %d",
                 (int)getpid(), (int)getpid());
    }
    else
      snprintf(cmdbuf, LINE_MAX - 1, "backtrace -w %d", (int)getpid());
  }
  system(cmdbuf);
#endif  /* 0 */

  system(xerror_bt_command);

  {
    struct sigaction sa;

    sa.sa_handler = SIG_DFL;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(signo, &sa, NULL);
    raise(signo);
  }
}


static struct {
  size_t cap;
  size_t cur;
  char **pat;
} ignore = { 0, 0, 0 };


static int
ign_reserve(void)
{
  void *p;

  if (ignore.cur >= ignore.cap) {
    if (!ignore.cap)
      ignore.cap = 32;
    ignore.cap *= 2;
    p = realloc(ignore.pat, ignore.cap);
    if (!p)
      return -1;

    ignore.pat = p;
  }
  return 0;
}


static int
ign_load_file(const char *pathname)
{
  FILE *fp;
  char *line = 0;
  size_t lnsize = 0;
  ssize_t len;

  fp = fopen(pathname, "r");
  if (!fp)
    return -1;

  while ((len = getline(&line, &lnsize, fp)) != -1) {
    if (line[len - 1] == '\n')
      line[len - 1] = '\0';
    if (line[0] == '\0' || line[0] == '#')
      continue;

    if (ign_reserve() == -1) {
      /* TODO: error handling */
      break;
    }

    ignore.pat[ignore.cur++] = strdup(line);
  }
  free(line);
  fclose(fp);

  return 0;
}


static int
ign_load(const char *basedir)
{
  const char *env = getenv(IGNORE_ENVNAME);
  int cwdfd;
  char cwdbuf[PATH_MAX], *cwd;

  if (env && ign_load_file(env) == 0)
    return 0;

  cwdfd = open(".", O_RDONLY);
  if (cwdfd == -1)
    return -1;

  while (1) {
    if (ign_load_file(IGNORE_FILENAME) == 0)
      break;

    cwd = getcwd(cwdbuf, PATH_MAX);
    if (cwd && strcmp(cwd, "/") == 0)
      break;

    if (chdir("..") == -1)
      break;
  }

  if (fchdir(cwdfd) != 0) {
    close(cwdfd);
    return -1;
  }

  close(cwdfd);
  return 0;
}


static int
ign_match(const char *src)
{
  size_t i;

  for (i = 0; i < ignore.cur; i++) {
    if (fnmatch(ignore.pat[i], src, FNM_FILE_NAME | FNM_LEADING_DIR) == 0)
      return 1;
  }
  return 0;
}


static void
ign_free(void)
{
  size_t i;
  char **pat = ignore.pat;
  size_t cur = ignore.cur;

  ignore.cur = 0;
  ignore.pat = 0;
  ignore.cap = 0;

  for (i = 0; i < cur; i++)
    free(pat[i]);

  free(pat);
}


static void
xerror_finalize(void)
{
  ign_free();
  free(xerror_bt_filename);
  free(xerror_bt_command);
}

static int
get_tid(void)
{
#ifdef _PTHREAD
# if defined(__linux__)
  return (int)syscall(SYS_gettid);
# elif defined(__APPLE__)
  return (int)pthread_mach_thread_np(pthread_self());
# else
#  error Not supported system
# endif
#else
  return 0;
#endif  /* _PTHREAD */
}


int
xerror_init(const char *prog_name, const char *ignore_search_dir)
{
  char *debug = getenv("XDEBUG");
  char *thread = getenv("XDEBUG_THREAD");

  if (prog_name)
    program_name = prog_name;

  if (debug) {
    if (strcmp(debug, "0") != 0)
      debug_mode = 1;
    else
      debug_mode = 0;
  }

  if (thread) {
    if (strcmp(thread, "0") != 0)
      printtid_mode = 1;
    else
      printtid_mode = 0;
  }

  if (ign_load(ignore_search_dir) != 0)
    return -1;

#ifdef _PTHREAD
  {
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&xerror_mutex, &attr);
    pthread_mutexattr_destroy(&attr);
  }
#endif  /* _PTHREAD */

  xerror_redirect(stderr);

  return 0;
}


static char *
find_executable(const char *exe)
{
  char *path;
  char *tok, *saveptr;
  char *fpath, *fullpath;

  path = getenv("PATH");
  if (!path)
    return 0;
  path = strdup(path);
  if (!path)
    return 0;

  tok = strtok_r(path, ":", &saveptr);
  do {
    if (!tok)
      break;

    asprintf(&fpath, "%s/%s", tok, exe);
#ifdef __USE_GNU
    fullpath = canonicalize_file_name(fpath);
#else
    fullpath = realpath(fpath, 0);
#endif
    free(fpath);

    if (fullpath && access(fullpath, X_OK) == 0) {
      free(path);
      return fullpath;
    }

    free(fullpath);
  } while ((tok = strtok_r(0, ":", &saveptr)) != 0);

  free(path);
  return 0;
}


int
xthread_set_name(const char *format, ...)
{
  int ret = -1;
  va_list ap;
  char *name;

  va_start(ap, format);
  if (vasprintf(&name, format, ap) == -1) {
    va_end(ap);
    return -1;
  }
  va_end(ap);

#ifdef _PTHREAD
#if defined(__linux__)
  ret = pthread_setname_np(pthread_self(), name);
  if (ret) {
    xdebug(ret, "pthread_setname_np failed");
    return -1;
  }
#elif defined(__APPLE__)
  ret = pthread_setname_np(name);
  if (ret) {
    xdebug(ret, "pthread_setname_np failed");
    return -1;
  }
#else

#endif
#endif  /* _PTHREAD */

  free(name);
  return ret;
}


const char *
xthread_get_name(char *buf, size_t sz)
{
#ifdef _PTHREAD
#if defined(__linux__)
  int ret;

  // if buffer size is not enough large to hold the thread name,
  // pthread_getname_np() returns ERANGE.
  assert(sz > 0);
  ret = pthread_getname_np(pthread_self(), buf, sz);
  if (ret) {
    xdebug(ret, "pthread_getname_np failed");
    buf[0] = '\0';
    return buf;
  }
  return buf;
#elif defined(__APPLE__)
  int ret;

  assert(sz > 0);
  ret = pthread_getname_np(pthread_self(), buf, sz);
  if (ret) {
    xdebug(ret, "pthread_getname_np failed");
    buf[0] = '\0';
    return buf;
  }
  return buf;
#endif
#endif  /* _PTHREAD */

  return "";
}


#ifdef _TEST_XERROR
#include <errno.h>

int debug_mode = 1;

static void bar(int a)
{
  unsigned char *p = 0;
  int i, j;
  i = 4;
  j = 0xdeadbeef;
  *p = 3;                       /* SIGSEGV */
}

void foo(int a, int b)
{
  FILE *fp;

  bar(a);
}


void
print_long(int fd, long value, int base)
{

}


int
main(int argc, char *argv[])
{
  xerror_init(0, 0);

  daemon(1, 1);

  xbacktrace_on_signals(SIGSEGV, SIGILL, SIGFPE, SIGBUS, 0);

  xerror(0, 0, "pid = %d\n", (int)getpid());
  xdebug(0, "program_name = %s", program_name);
  xdebug(0, "this is debug message %d", 1);

  if (argc != 2)
    xerror(1, 0, "argument required, argc = %d", argc);

  xerror(0, EINVAL, "invalid argv[1] = %s", argv[1]);

  foo(1, 3);
  return 0;
}

#endif  /* _TEST_XERROR */
