/*
 * libev-based HTTP server implementation
 * Copyright (C) 2014  Seong-Kook Shin <cinsky@gmail.com>
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */
#include <assert.h>
#include <errno.h>
#include <limits.h>

#define USE_PCRE

#ifdef USE_PCRE
#include <pcre.h>

#ifndef PCRE_STUDY_JIT_COMPILE
#define PCRE_STUDY_JIT_COMPILE 0
#endif
#else
#include <regex.h>
#endif

#include "xerror.h"
#include "xobstack.h"
#include "patable.h"

// typedef void (*pat_callback)(int grpc, char *grpv[]);

struct pentry {
#ifdef USE_PCRE
  pcre *re;
  pcre_extra *ext;
#else
  int used;
  regex_t re;
#endif
  void *data;
};

#define OVECTOR_MAX     63      /* should be a multiple of three */


/*
  int idx = patable_match(&ngroup);
  char *grpv = patable_groups(pool, ngroup);
  cb[idx](ngroup, grpv);
  ptable_release(pool, grpv);
*/


void *
patable_data(struct patable *table, int index)
{
  assert(index >= 0);
  assert(index <= table->npat);

  return table->pat[index].data;
}

void
patable_free_groups(struct xobs *pool, char **grpv)
{
  assert(xobs_object_size(pool) == 0);
  xobs_free(pool, grpv);
}


#ifdef USE_PCRE
int
patable_add(struct patable *table, const char *pattern,
            const void *data)
{
  int i;
  struct pentry *p;
  size_t newsz;
  int ecode, eoff;
  const char *emsg;

  // int options = PCRE_ANCHORED | PCRE_DOLLAR_ENDONLY;
  int options = PCRE_ANCHORED;

  if (table->cur >= table->npat) {
    /* TODO: check if there's a bug here */
    newsz = table->npat * 2;
    p = realloc(table->pat, sizeof(*p) * newsz);
    if (!p)
      return 0;
    for (i = table->npat; i < newsz; i++) {
      table->pat[i].re = 0;
    }
    table->pat = p;
    table->npat = newsz;
  }

  for (i = table->cur; i < table->npat; i++) {
    if (table->pat[i].re == 0) {
      table->pat[i].re = pcre_compile2(pattern, options,
                                       &ecode, &emsg, &eoff, NULL);
      if (!table->pat[i].re) {
        xdebug(0, "invalid regular expresssion in \"%s\": %s", pattern, emsg);
        return 0;
      }
      table->pat[i].ext = pcre_study(table->pat[i].re,
                                     PCRE_STUDY_EXTRA_NEEDED |
                                     PCRE_STUDY_JIT_COMPILE,
                                     &emsg);

      if (!table->pat[i].ext) {
        xdebug(0, "analyzing regular expresssion in \"%s\": %s", pattern, emsg);
        pcre_free(table->pat[i].re);
        table->pat[i].re = 0;
        return 0;
      }
      table->pat[i].data = (void *)data;

      table->cur = i + 1;
      return 1;
    }
  }

  table->cur = i;
  return patable_add(table, pattern, data);
}


int
patable_match(struct patable *table, const char *source, size_t len,
              int *ngroup, int *ovector, size_t ovsize)
{
  int i;
  int ng;

  if (len == (size_t)-1)
    len = strlen(source);

  for (i = 0; i < table->cur; i++) {
    assert(table->pat[i].re != 0);
    ng = re_match(table->pat[i].re, table->pat[i].ext, source, len,
                  ovector, ovsize);
    if (ng > 0) {
      *ngroup = ng;
      return i;
    }
  }
  return -1;
}


char **
patable_groups(struct xobs *pool, size_t ngroup,
               const char *source, const int *ovector)
{
  char **grpv;
  int i;

  if (ngroup == 0)
    return 0;

  grpv = xobs_alloc(pool, sizeof(*grpv) * ngroup);
  if (!grpv)
    return 0;

  for (i = 0; i < ngroup; i++) {
    grpv[i] = xobs_copy0(pool, source + ovector[i << 1],
                         ovector[(i << 1) + 1] - ovector[i << 1]);
    if (!grpv[i]) {
      xdebug(errno, "allocating ovector string for reg exec failed");
      xobs_free(pool, grpv);
      return 0;
    }
  }
  return grpv;
}

#else  /* USE_PCRE */

int
patable_add(struct patable *table, const char *pattern,
            const void *data)
{
  int i;
  struct pentry *p;
  size_t newsz;
  int ecode;

  if (table->cur >= table->npat) {
    /* TODO: check if there's a bug here */
    newsz = table->npat * 2;
    p = realloc(table->pat, sizeof(*p) * newsz);
    if (!p)
      return 0;

    for (i = table->npat; i < newsz; i++) {
      table->pat[i].used = 0;
    }
    table->pat = p;
    table->npat = newsz;
  }

  for (i = table->cur; i < table->npat; i++) {
    if (!table->pat[i].used) {
      ecode = regcomp(&table->pat[i].re, pattern, REG_EXTENDED);
      if (ecode != 0) {
        char buf[LINE_MAX];
        regerror(ecode, &table->pat[i].re, buf, sizeof(buf));
        xdebug(0, "invalid regular expression in \"%s\": %s", pattern, buf);
        return 0;
      }
      table->pat[i].data = (void *)data;
      table->cur = i + 1;
      table->pat[i].used = 1;
      return 1;
    }
  }

  table->cur = i;
  return patable_add(table, pattern, data);
}


int
patable_match(struct patable *table, const char *source, size_t len,
              int *ngroup, regmatch_t *ovector, size_t ovsize)
{
  int i, j;

  for (i = 0; i < table->cur; i++) {
    if (regexec(&table->pat[i].re, source, ovsize, ovector, 0) == 0) {
      j = 0;
      while (j < ovsize && ovector[j].rm_so != -1)
        j++;
      *ngroup = j;
      return i;
    }
  }
  return -1;
}


char **
patable_groups(struct xobs *pool, size_t ngroup,
               const char *source, const regmatch_t *ovector)
{
  char **grpv;
  int i;

  grpv = xobs_alloc(pool, sizeof(*grpv) * ngroup);
  if (!grpv)
    return 0;

  for (i = 0; i < ngroup; i++) {
    grpv[i] = xobs_copy0(pool, source + ovector[i].rm_so,
                         ovector[i].rm_eo - ovector[i].rm_so);
    if (!grpv[i]) {
      xdebug(errno, "allocating ovector string for reg exec failed");
      xobs_free(pool, grpv);
      return 0;
    }
  }
  return grpv;
}

#endif  /* USE_PCRE */




#if 0
int
patable_exec(struct patable *table, const char *source, size_t len,
             struct xobs *pool)
{
  int i, j;
  int ovec[OVECTOR_MAX];
  int ngroup;

  char **gvec;

  assert(xobs_object_size(pool) == 0);

  if (len == (size_t)-1)
    len = strlen(source);

  for (i = 0; i < table->cur; i++) {
    assert(table->pat[i].re != 0);
    ngroup = pcre_exec(table->pat[i].re, table->pat[i].ext,
                       source, len,
                       0, /* start offset */
                       0, /* options */
                       ovec, sizeof(ovec) / sizeof(ovec[0]));

    if (ngroup > 0) {
      gvec = xobs_alloc(pool, sizeof(char *) * ngroup);
      if (!gvec) {
        xdebug(errno, "allocating ovector for reg exec failed");
        return 0;
      }

      for (j = 0; j < ngroup; j++) {
        // g0: 0 1
        // g1: 2 3
        // g2: 4 5
        //
        // j = 0 1 2

        gvec[j] = xobs_copy0(pool, source + ovec[j << 1],
                             ovec[(j << 1) + 1] - ovec[j << 1]);
        if (!gvec[j]) {
          xdebug(errno, "allocating ovector string for reg exec failed");
          xobs_free(pool, gvec);
          return 0;
        }
      }
      //table->pat[i].cb(ngroup, gvec);
      xobs_free(pool, gvec);
      return 1;
    }
  }

  return 0;
}
#endif  /* 0 */




int
patable_init(struct patable *pat)
{
  int i;
  struct pentry *p;

  pat->cur = 0;
  pat->npat = 16;
  pat->pat = malloc(sizeof(*p) * pat->npat);
  if (!pat->pat)
    return 0;

  for (i = 0; i < pat->npat; i++) {
#ifdef USE_PCRE
    pat->pat[i].re = 0;
    pat->pat[i].ext = 0;
#else
    pat->pat[i].used = 0;
#endif
  }

  return 1;
}


void
patable_release(struct patable *pat)
{
  int i;

  for (i = 0; i < pat->npat; i++) {
#ifdef USE_PCRE
    pcre_free(pat->pat[i].re);
    pat->pat[i].re = 0;
    pcre_free_study(pat->pat[i].ext);
    pat->pat[i].ext = 0;
#else
    regfree(&pat->pat[i].re);
    pat->pat[i].used = 0;
#endif
  }

}


#ifdef TEST_PATABLE
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

void
my_callback(int argc, char *argv[])
{
  int i;
  for (i = 0; i < argc; i++) {
    printf("group[%d] = |%s|\n", i, argv[i]);
  }
}


void
timespec_normalize(struct timespec *ts)
{
  long t;

  if (ts->tv_nsec > 0) {
    ts->tv_sec += ts->tv_nsec / 1000000000;
    ts->tv_nsec = ts->tv_nsec % 1000000000;
  }
  else {
    ts->tv_nsec = labs(ts->tv_nsec);
    t = (ts->tv_nsec + 999999999) / 1000000000;
    ts->tv_sec -= t;
    ts->tv_nsec = t * 1000000000 - ts->tv_nsec;
  }
}


void
timespec_diff(struct timespec *sum,
              const struct timespec *begin, const struct timespec *end)
{
  struct timespec ts;
  ts.tv_nsec = end->tv_nsec - begin->tv_nsec;
  ts.tv_sec = end->tv_sec - begin->tv_sec;

  sum->tv_sec += ts.tv_sec;
  sum->tv_nsec += ts.tv_nsec;
  timespec_normalize(sum);
}


int
main(int argc, char *argv[])
{
  struct xobs pool_;
  struct xobs *pool = &pool_;
  struct patable tbl;
  int i;
  char buf[LINE_MAX];
  struct timespec sum, ts1, ts2;

  xobs_init(pool);

  patable_init(&tbl);

  if (argc == 1) {
#if 0
    patable_add(&tbl, "/config", 0);
    patable_add(&tbl, "/person/(.*)", 0);
    patable_add(&tbl, "/alldocs/(.*)", 0);
    patable_add(&tbl, "/config2", 0);
    patable_add(&tbl, "/config3", 0);
    patable_add(&tbl, "/config4", 0);
    patable_add(&tbl, "/config5", 0);
#endif

    patable_add(&tbl, "/db/([^/]+)/([^/]+)/?", 0);

    sum.tv_sec = sum.tv_nsec = 0;

    for (i = 0; i < 1000000; i++) {
      int ngroup;
#ifdef USE_PCRE
      int ovector[80];
#else
      regmatch_t ovector[40];
#endif
      char **grpv;
      int idx;

      snprintf(buf, LINE_MAX - 1, "/db/%ld/%ld/", random(), random());
      printf("source: |%s|\n", buf);

      clock_gettime(CLOCK_MONOTONIC, &ts1);
      idx = patable_match(&tbl, buf, (size_t)-1,
                          &ngroup,
                          ovector, sizeof(ovector) / sizeof(ovector[0]));
      if (idx != -1) {
        grpv = patable_groups(pool, ngroup, buf, ovector);
        //my_callback(ngroup, grpv);
        patable_free_groups(pool, grpv);
      }
      clock_gettime(CLOCK_MONOTONIC, &ts2);
      timespec_diff(&sum, &ts1, &ts2);
    }
    fprintf(stderr, "time: %ld.%09ld\n", sum.tv_sec, sum.tv_nsec);
  }
  else if (argc == 3) {
    int fd;
    char buf[4096];
    int readch;
    int ngroup;
    int ovector[80];
    char **grpv;
    int idx;

    patable_add(&tbl, argv[1], 0);

    fd = open(argv[2], O_RDONLY);
    if (fd == -1)
      xerror(1, errno, "can't open %s", argv[2]);

    readch = read(fd, buf, sizeof(buf));
    if (readch == -1)
      xerror(1, errno, "read failed");
    close(fd);

    idx = patable_match(&tbl, buf, readch,
                        &ngroup,
                        ovector, sizeof(ovector) / sizeof(ovector[0]));
    printf("match(%d), ngroup(%d)\n", idx, ngroup);

    if (idx != -1) {
      grpv = patable_groups(pool, ngroup, buf, ovector);
      for (i = 0; i < ngroup; i++) {
        printf("group[%d] = |%s|\n", i, grpv[i]);
      }
      patable_free_groups(pool, grpv);
    }
    else
      printf("no match\n");
  }

  patable_release(&tbl);
  xobs_free(pool, 0);

  return 0;
}

#endif  /* TEST_PATABLE */
