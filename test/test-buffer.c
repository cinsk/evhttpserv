#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <check.h>
#include "buffer.h"
#include "xerror.h"

#define BLKSIZE 8196

START_TEST(test_buffer_fill_fd)
{
  struct buffer b;
  struct stat sbuf;
  int fd, eof;
  ssize_t readch;

  buffer_init(&b, 40);

  fd = open("test-buffer.c", O_RDONLY);
  ck_assert_int_ne(fd, -1);
  ck_assert_int_ne(fstat(fd, &sbuf), -1);

  readch = buffer_fill_fd(&b, fd, (size_t)-1, &eof);

  ck_assert_int_eq(sbuf.st_size, readch);
  ck_assert_int_eq(sbuf.st_size, buffer_size(&b, 0));

  close(fd);
  // buffer_clear(&b);
}
END_TEST


static void
set_nonblock(int fd)
{
  int flags;

  flags = fcntl(fd, F_GETFL);
  if (flags == -1)
    xerror(1, errno, "fcntl failed");
  if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
    xerror(1, errno, "fcntl failed");
}

static void *
producer_proc(void *data)
{
  int *argv = (int *)data;
  int fd = argv[0];
  int size = argv[1];
  /* argv[0] = write end fd, argv[1] = size of byte(s) to produce */
  int total = 0;
  char buf[BLKSIZE];
  int written;

  xerror(0, 0, "data: %p, size: %d, fd = %d\n", data, size, fd);

  free(argv);

  while (total < size) {
    int sz = (total + BLKSIZE < size) ? BLKSIZE : size - total;
    written = write(fd, buf, sz);

    if (written == -1) {
      if (errno != EINTR && errno != EAGAIN) {
        xerror(0, errno, "producer: write(2) failed");
        break;
      }
    }
    else {
      total += written;
    }
  }
  close(fd);
  return NULL;
}


static void
end_producer(pthread_t *thread)
{
  void *retval;
  pthread_join(*thread, &retval);
}

static int
start_producer(size_t size, pthread_t *thread)
{
  int fds[2];
  int *arg;
  int err;

  if (socketpair(PF_LOCAL, SOCK_STREAM, 0, fds) == -1) {
    xerror(0, errno, "socketpair failed");
    return -1;
  }

  arg = malloc(sizeof(*arg) * 2);
  arg[0] = fds[1];
  arg[1] = (int)size;

  xerror(0, 0, "arg: %p", arg);
  err = pthread_create(thread, NULL, producer_proc, arg);
  if (err) {
    xerror(0, err, "pthread_create failed");
    close(fds[0]);
    close(fds[1]);
    return -1;
  }

  set_nonblock(fds[0]);
  return fds[0];
}


Suite *
buffer_suite(void)
{
  Suite *s = suite_create("buffer");

  TCase *tc_core = tcase_create("Core");
  tcase_add_test(tc_core, test_buffer_fill_fd);
  suite_add_tcase(s, tc_core);

  return s;
}

int debug_mode = 1;

int
smain(int argc, char *argv[])
{
  pthread_t producer;
  struct buffer b;
  int fd;
  ssize_t readch;
  int eof;

  buffer_init(&b, 40);

  fd = start_producer(8196 * 10, &producer);
  if (fd == -1)
    xerror(1, errno, "start_producer failed");

  xdebug(0, "before buffer_fill_fd");
  readch = buffer_fill_fd(&b, fd, (size_t)-1, &eof);
  printf("readch = %zd\n", readch);

  end_producer(&producer);
  close(fd);

  return 0;
}

int
main(int argc, char *argv[])
{
  int nfailed;
  Suite *s = buffer_suite();
  SRunner *sr = srunner_create(s);
  srunner_run_all(sr, CK_VERBOSE);
  nfailed = srunner_ntests_failed(sr);
  srunner_free(sr);

  return (nfailed == 0);
}
