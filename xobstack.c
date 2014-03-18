/*
 * xobstack.c - subrotunes used implicitly by object stack macros
 * Copyright (C) 2012  Seong-Kook Shin <cinsky@gmail.com>
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
 *
 */

/*
 * Xobstack is almost identical to the GNU obstack, except few things:
 *
 * - provides better error handling; all allocation function will return
 *   error codes.
 *
 * - thread safe; since it does not have global failure handling function
 *   (as in obstack, obstack_alloc_failed_handler)
 *
 * - debugging support -- by defining DEBUG macro before compiling,
 *   you can verify your code with the help of external tools (such as
 *   valgrind, efence, duma.)
 *
 * - different supported platform -- Xobstack supports GNU C or other C
 *   compilers that support inline functions.  Unlike obstack, old C
 *   compilers are not supported.
 */

/*
 * The mother obstack code is copied from glibc-2.14.1, modified for
 * Darwin compilation -- cinsk
 */
#include <stdarg.h>
#include <stdint.h>

#include "xobstack.h"

#ifdef DEBUG
#include <unistd.h>
#endif

/* Comment out all this code if we are using the GNU C Library, and are not
   actually compiling the library itself, and the installed library
   supports the same library interface we do.  This code is part of the GNU
   C Library, but also included in many other GNU distributions.  Compiling
   and linking in this code is a waste when using the GNU C library
   (especially if it is a shared library).  Rather than having every GNU
   program understand `configure --with-gnu-libc' and omit the object
   files, it is simpler to just do this in the source for each such file.  */

#include <stdio.h>              /* Random thing to get __GNU_LIBRARY__.  */
#if !defined _LIBC && defined __GNU_LIBRARY__ && __GNU_LIBRARY__ > 1
# include <gnu-versions.h>
# if _GNU_OBSTACK_INTERFACE_VERSION == OBSTACK_INTERFACE_VERSION
#  define ELIDE_CODE
# endif
#endif

#include <stddef.h>

# if HAVE_INTTYPES_H
#  include <inttypes.h>
# endif
# if HAVE_STDINT_H || defined _LIBC || defined __APPLE__
#  include <stdint.h>
# endif

#ifdef DEBUG
#include <stdarg.h>

#define CALL_DALLOCFUN(h, p, size)     ((*(h)->dallocfun) (p, size))

#define LOC_PARAMSPEC   const char *filename__, int lineno__
#define LOC_PARAMS      filename__, lineno__
#define PARAM_NAME      filename__
#define PARAM_LINE      lineno__

#define ABORT(...) d_xobs_abort(PARAM_NAME, PARAM_LINE, __VA_ARGS__)

#define CHECK_UNINIT(h, name)   do {                            \
    if ((h)->d_stack == (struct d_xobs_stack_chunk *)-1)        \
      ABORT("%s: xobs is uninitialized state", name);           \
  } while (0)

static int d_xobs_add_chunk (struct xobs *h);
static void d_xobs_free_chunk(struct xobs *h, struct d_xobs_stack_chunk *until);
static int d_xobs_blank_(LOC_PARAMSPEC, const char *fname,
                         struct xobs *h, int size);
static void *d_xobs_alloc_(LOC_PARAMSPEC, const char *fname,
                           struct xobs *h, int size);
#endif

#ifdef TEST_XOBS
#include <stdlib.h>

#define xobs_chunk_alloc        malloc
#define xobs_chunk_free         free

// #define xobs_printf_grow(obs, ...) __VA_ARGS__


int
main(int argc, char *argv[])
{
  struct xobs xo;
  int *ip;
  char *cp;

  xobs_init(&xo);

  {
    ip = xobs_alloc(&xo, sizeof(int));
    *ip = 0xdeadbeef;
  }

  {
    int i;
    void *base = xobs_alloc(&xo, 1);
    void *p;

    for (i = 0; i < 1000; i++) {
      p = xobs_alloc(&xo, 5);
      strcpy(p, "asdf");
    }
    xobs_free(&xo, base);
  }

  {
    int i;
    for (i = 0; i < 'z' - 'a' + 1; i++) {
      printf("growing: %d size\n", xobs_object_size(&xo));
      xobs_1grow(&xo, 'a' + i);
    }
    xobs_1grow(&xo, '\0');
    cp = xobs_finish(&xo);
    printf("grown result: |%s|\n", cp);
  }

  {
    char *p;
    xobs_grow(&xo, "asdf", 4);
    xobs_grow(&xo, "qwer", 4);
    xobs_grow(&xo, "zxcv", 4);
    xobs_sprintf(&xo, "hei%s", "hi");
    xobs_sprintf0(&xo, "mai%s", "ti");
    //xobs_1grow(&xo, '\0');

    {
      char *b = xobs_base(&xo);
      printf("base: %s\n", b);
    }

    p = xobs_finish(&xo);
    printf("grown result: |%s|\n", p);
    xobs_free(&xo, ip);
  }

  xobs_free(&xo, NULL);
  return 0;
}

#undef xobs_chunk_alloc
#undef xobs_chunk_free

#endif  /* TEST_XOBS */


/* Determine default alignment.  */
union fooround
{
  uintmax_t i;
  long double d;
  void *p;
};
struct fooalign
{
  char c;
  union fooround u;
};
/* If malloc were really smart, it would round addresses to DEFAULT_ALIGNMENT.
   But in fact it might be less smart and round addresses to as much as
   DEFAULT_ROUNDING.  So we prepare for it to do that.  */
enum
  {
    DEFAULT_ALIGNMENT = offsetof (struct fooalign, u),
    DEFAULT_ROUNDING = sizeof (union fooround)
  };

/* When we copy a long block of data, this is the unit to do it with.
   On some machines, copying successive ints does not work;
   in such a case, redefine COPYING_UNIT to `long' (if that works)
   or `char' as a last resort.  */
# ifndef COPYING_UNIT
#  define COPYING_UNIT int
# endif


/* The functions allocating more room by calling `xobs_chunk_alloc'
   jump to the handler pointed to by `xobs_alloc_failed_handler'.
   This can be set to a user defined function which should either
   abort gracefully or use longjump - but shouldn't return.  This
   variable by default points to the internal function
   `print_and_abort'.  */
static void print_and_abort (void);
void (*xobs_alloc_failed_handler) (void) = print_and_abort;

/* Exit value used when `print_and_abort' is used.  */
# include <stdlib.h>
# if defined(_LIBC) || defined(__APPLE__)
int xobs_exit_failure = EXIT_FAILURE;
# else
#  define xobs_exit_failure 1
# endif

/* Define a macro that either calls functions with the traditional malloc/free
   calling interface, or calls functions with the mmalloc/mfree interface
   (that adds an extra first argument), based on the state of use_extra_arg.
   For free, do not use ?:, since some compilers, like the MIPS compilers,
   do not allow (expr) ? void : void.  */

# define CALL_CHUNKFUN(h, size) \
  (((h) -> use_extra_arg) \
   ? (*(h)->chunkfun) ((h)->extra_arg, (size)) \
   : (*(struct _xobs_chunk *(*) (long)) (h)->chunkfun) ((size)))

# define CALL_FREEFUN(h, old_chunk) \
  do { \
    if ((h) -> use_extra_arg) \
      (*(h)->freefun) ((h)->extra_arg, (old_chunk)); \
    else \
      (*(void (*) (void *)) (h)->freefun) ((old_chunk)); \
  } while (0)


/* Initialize an xobs H for use.  Specify chunk size SIZE (0 means default).
   Objects start on multiples of ALIGNMENT (0 means use default).
   CHUNKFUN is the function to use to allocate chunks,
   and FREEFUN the function to free them.

   Return nonzero if successful, calls xobs_alloc_failed_handler if
   allocation fails.  */

int
_xobs_begin (struct xobs *h,
             int size, int alignment,
             void *(*chunkfun) (long),
             void (*freefun) (void *))
{
  register struct _xobs_chunk *chunk; /* points to new chunk */

  if (alignment == 0)
    alignment = DEFAULT_ALIGNMENT;
  if (size == 0)
    /* Default size is what GNU malloc can fit in a 4096-byte block.  */
    {
      /* 12 is sizeof (mhead) and 4 is EXTRA from GNU malloc.
         Use the values for range checking, because if range checking is off,
         the extra bytes won't be missed terribly, but if range checking is on
         and we used a larger request, a whole extra 4096 bytes would be
         allocated.

         These number are irrelevant to the new GNU malloc.  I suspect it is
         less sensitive to the size of the request.  */
      int extra = ((((12 + DEFAULT_ROUNDING - 1) & ~(DEFAULT_ROUNDING - 1))
                    + 4 + DEFAULT_ROUNDING - 1)
                   & ~(DEFAULT_ROUNDING - 1));
      size = 4096 - extra;
    }

  h->chunkfun = (struct _xobs_chunk * (*)(void *, long)) chunkfun;
  h->freefun = (void (*) (void *, struct _xobs_chunk *)) freefun;
  h->chunk_size = size;
  h->alignment_mask = alignment - 1;
  h->use_extra_arg = 0;

  chunk = h->chunk = CALL_CHUNKFUN (h, h -> chunk_size);
  if (!chunk) {
    if (h->failfun)
      (*h->failfun)(h);
    else {
      if (xobs_alloc_failed_handler)
        (*xobs_alloc_failed_handler) ();
    }
    return 0;
  }
  h->next_free = h->object_base = __PTR_ALIGN ((char *) chunk, chunk->contents,
                                               alignment - 1);
  h->chunk_limit = chunk->limit
    = (char *) chunk + h->chunk_size;
  chunk->prev = 0;
  /* The initial chunk now contains no empty object.  */
  h->maybe_empty_object = 0;
#ifdef NO_LEGACY
  h->alloc_failed = 0;
#endif
  return 1;
}

int
_xobs_begin_1 (struct xobs *h, int size, int alignment,
               void *(*chunkfun) (void *, long),
               void (*freefun) (void *, void *),
               void *arg)
{
  register struct _xobs_chunk *chunk; /* points to new chunk */

  if (alignment == 0)
    alignment = DEFAULT_ALIGNMENT;
  if (size == 0)
    /* Default size is what GNU malloc can fit in a 4096-byte block.  */
    {
      /* 12 is sizeof (mhead) and 4 is EXTRA from GNU malloc.
         Use the values for range checking, because if range checking is off,
         the extra bytes won't be missed terribly, but if range checking is on
         and we used a larger request, a whole extra 4096 bytes would be
         allocated.

         These number are irrelevant to the new GNU malloc.  I suspect it is
         less sensitive to the size of the request.  */
      int extra = ((((12 + DEFAULT_ROUNDING - 1) & ~(DEFAULT_ROUNDING - 1))
                    + 4 + DEFAULT_ROUNDING - 1)
                   & ~(DEFAULT_ROUNDING - 1));
      size = 4096 - extra;
    }

  h->chunkfun = (struct _xobs_chunk * (*)(void *,long)) chunkfun;
  h->freefun = (void (*) (void *, struct _xobs_chunk *)) freefun;
  h->chunk_size = size;
  h->alignment_mask = alignment - 1;
  h->extra_arg = arg;
  h->use_extra_arg = 1;

  chunk = h->chunk = CALL_CHUNKFUN (h, h -> chunk_size);
  if (!chunk) {
    if (h->failfun)
      (*h->failfun)(h);
    else {
      if (xobs_alloc_failed_handler)
        (*xobs_alloc_failed_handler) ();
    }
    return 0;
  }
  h->next_free = h->object_base = __PTR_ALIGN ((char *) chunk, chunk->contents,
                                               alignment - 1);
  h->chunk_limit = chunk->limit
    = (char *) chunk + h->chunk_size;
  chunk->prev = 0;
  /* The initial chunk now contains no empty object.  */
  h->maybe_empty_object = 0;
#ifdef NO_LEGACY
  h->alloc_failed = 0;
#endif
  return 1;
}

/* Allocate a new current chunk for the xobs *H
   on the assumption that LENGTH bytes need to be added
   to the current object, or a new object of length LENGTH allocated.
   Copies any partial object from the end of the old chunk
   to the beginning of the new one.  */

int
_xobs_newchunk (struct xobs *h, int length)
{
  register struct _xobs_chunk *old_chunk = h->chunk;
  register struct _xobs_chunk *new_chunk;
  register long new_size;
  register long obj_size = h->next_free - h->object_base;
  register long i;
  long already;
  char *object_base;

  /* Compute size for new chunk.  */
  new_size = (obj_size + length) + (obj_size >> 3) + h->alignment_mask + 100;
  if (new_size < h->chunk_size)
    new_size = h->chunk_size;

  /* Allocate and initialize the new chunk.  */
  new_chunk = CALL_CHUNKFUN (h, new_size);
  if (!new_chunk) {
    if (h->failfun)
      (*h->failfun)(h);
    else {
      if (xobs_alloc_failed_handler)
        (*xobs_alloc_failed_handler) ();
    }
    return 0;
  }

  h->chunk = new_chunk;
  new_chunk->prev = old_chunk;
  new_chunk->limit = h->chunk_limit = (char *) new_chunk + new_size;

  /* Compute an aligned object_base in the new chunk */
  object_base =
    __PTR_ALIGN ((char *) new_chunk, new_chunk->contents, h->alignment_mask);

  /* Move the existing object to the new chunk.
     Word at a time is fast and is safe if the object
     is sufficiently aligned.  */
  if (h->alignment_mask + 1 >= DEFAULT_ALIGNMENT)
    {
      for (i = obj_size / sizeof (COPYING_UNIT) - 1;
           i >= 0; i--)
        ((COPYING_UNIT *)object_base)[i]
          = ((COPYING_UNIT *)h->object_base)[i];
      /* We used to copy the odd few remaining bytes as one extra COPYING_UNIT,
         but that can cross a page boundary on a machine
         which does not do strict alignment for COPYING_UNITS.  */
      already = obj_size / sizeof (COPYING_UNIT) * sizeof (COPYING_UNIT);
    }
  else
    already = 0;
  /* Copy remaining bytes one by one.  */
  for (i = already; i < obj_size; i++)
    object_base[i] = h->object_base[i];

  /* If the object just copied was the only data in OLD_CHUNK,
     free that chunk and remove it from the chain.
     But not if that chunk might contain an empty object.  */
  if (! h->maybe_empty_object
      && (h->object_base
          == __PTR_ALIGN ((char *) old_chunk, old_chunk->contents,
                          h->alignment_mask)))
    {
      new_chunk->prev = old_chunk->prev;
      CALL_FREEFUN (h, old_chunk);
    }

  h->object_base = object_base;
  h->next_free = h->object_base + obj_size;
  /* The new chunk certainly contains no empty object yet.  */
  h->maybe_empty_object = 0;

  return 1;
}

/* Return nonzero if object OBJ has been allocated from xobs H.
   This is here for debugging.
   If you use it in a program, you are probably losing.  */

/* Suppress -Wmissing-prototypes warning.  We don't want to declare this in
   xobs.h because it is just for debugging.  */
int _xobs_allocated_p (struct xobs *h, void *obj);

int
_xobs_allocated_p (struct xobs *h, void *obj)
{
  register struct _xobs_chunk *lp;   /* below addr of any objects in this chunk */
  register struct _xobs_chunk *plp;  /* point to previous chunk if any */

  lp = (h)->chunk;
  /* We use >= rather than > since the object cannot be exactly at
     the beginning of the chunk but might be an empty object exactly
     at the end of an adjacent chunk.  */
  while (lp != 0 && ((void *) lp >= obj || (void *) (lp)->limit < obj))
    {
      plp = lp->prev;
      lp = plp;
    }
  return lp != 0;
}

/* Free objects in xobs H, including OBJ and everything allocate
   more recently than OBJ.  If OBJ is zero, free everything in H.  */

# undef xobs_free

void
xobs_free (struct xobs *h, void *obj)
{
  register struct _xobs_chunk *lp;   /* below addr of any objects in this chunk */
  register struct _xobs_chunk *plp;  /* point to previous chunk if any */

  lp = h->chunk;
  /* We use >= because there cannot be an object at the beginning of a chunk.
     But there can be an empty object at that address
     at the end of another chunk.  */
  while (lp != 0 && ((void *) lp >= obj || (void *) (lp)->limit < obj))
    {
      plp = lp->prev;
      CALL_FREEFUN (h, lp);
      lp = plp;
      /* If we switch chunks, we can't tell whether the new current
         chunk contains an empty object, so assume that it may.  */
      h->maybe_empty_object = 1;
    }
  if (lp)
    {
      h->object_base = h->next_free = (char *) (obj);
      h->chunk_limit = lp->limit;
      h->chunk = lp;
    }
  else if (obj != 0)
    /* obj is not in any of the chunks! */
    abort ();
}


int
_xobs_memory_used (struct xobs *h)
{
  register struct _xobs_chunk* lp;
  register int nbytes = 0;

  for (lp = h->chunk; lp != 0; lp = lp->prev)
    {
      nbytes += lp->limit - (char *) lp;
    }
  return nbytes;
}

/* Define the error handler.  */
# ifdef _LIBC
#  include <libintl.h>
# else
#  ifdef USE_GETTEXT
#   include "gettext.h"
#  endif
# endif  /* _LIBC */
# ifndef _
#  ifndef USE_GETTEXT
#   define _(msgid) msgid
#  else
#   define _(msgid) gettext (msgid)
#  endif
# endif

# ifdef _LIBC
#  include <libio/iolibio.h>
# endif

# ifndef __attribute__
/* This feature is available in gcc versions 2.5 and later.  */
#  if __GNUC__ < 2 || (__GNUC__ == 2 && __GNUC_MINOR__ < 5)
#   define __attribute__(Spec) /* empty */
#  endif
# endif

static void
__attribute__ ((noreturn))
print_and_abort (void)
{
  /* Don't change any of these strings.  Yes, it would be possible to add
     the newline to the string and use fputs or so.  But this must not
     happen because the "memory exhausted" message appears in other places
     like this and the translation should be reused instead of creating
     a very similar string which requires a separate translation.  */
# ifdef _LIBC
  (void) __fxprintf (NULL, "%s\n", _("memory exhausted"));
# else
  fprintf (stderr, "%s\n", _("memory exhausted"));
# endif
  exit (xobs_exit_failure);
}


#ifdef DEBUG

static void
d_xobs_abort (LOC_PARAMSPEC, const char *fmt, ...)
{
  va_list ap;

  fflush(stdout);
  fflush(stderr);

  flockfile(stderr);
  fprintf(stderr, "%s:%d: ", PARAM_NAME, PARAM_LINE);
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);

  fputc('\n', stderr);
  funlockfile(stderr);
  fflush(stderr);

  abort();
}


int
d_xobs_add_chunk (struct xobs *h)
{
  struct d_xobs_stack_chunk *p;
  int i;

  p = malloc(sizeof(*p) + sizeof(void *) * (h->d_nelems - 1));
  if (!p) {
    xobs_callfail(h);
    return 0;
  }

  for (i = 0; i < h->d_nelems; i++) {
    p->ptrs[i] = NULL;
  }
  p->current = 0;
  p->prev = p->next = NULL;

  if (h->d_stack) {
    h->d_stack->next = p;
    p->prev = h->d_stack;
  }
  h->d_stack = p;

  return 1;
}


int
d_xobs_begin(LOC_PARAMSPEC,
             struct xobs *h, int size, int alignment,
             void *(*chunkfun) (long),
             void (*freefun) (void *),
             void *(*dallocfun) (void *, size_t))
{
  memset(h, 0, sizeof(*h));

  if (alignment == 0)
    alignment = DEFAULT_ALIGNMENT;
  h->chunkfun = (struct _xobs_chunk * (*)(void *, long)) chunkfun;
  h->freefun = (void (*) (void *, struct _xobs_chunk *)) freefun;
  h->dallocfun = dallocfun;

  {
    int extra = ((((12 + DEFAULT_ROUNDING - 1) & ~(DEFAULT_ROUNDING - 1))
                  + 4 + DEFAULT_ROUNDING - 1)
                 & ~(DEFAULT_ROUNDING - 1));
    long size = sysconf(_SC_PAGESIZE);

    if (size == -1) {
      /* cannot get the size of the page */
      size = 4096;
    }
    size -= extra + sizeof(struct d_xobs_stack_chunk) - sizeof(void *);
    h->d_nelems = size / sizeof(void *);
    h->d_stack = NULL;
    h->d_growing = 0;
    h->d_growsize = 0;
    h->d_roomsize = 0;

    printf("extra: %d\n", extra);
    printf("nelem: %zd\n", h->d_nelems);
  }

  return d_xobs_add_chunk(h);
}


void *
d_xobs_alloc(LOC_PARAMSPEC, struct xobs *h, int size)
{
  return d_xobs_alloc_(LOC_PARAMS, "xobs_alloc", h, size);
}


static void *
d_xobs_alloc_(LOC_PARAMSPEC, const char *fname, struct xobs *h, int size)
{
  void *p;

  CHECK_UNINIT(h, fname);

  if (h->d_growing)
    ABORT("%s: growing object detected", fname);

  if (h->d_stack->current >= h->d_nelems - 1)
    if (!d_xobs_add_chunk(h))
      return 0;

  p = CALL_DALLOCFUN(h, 0, size);
  if (!p) {
    xobs_callfail(h);
    return 0;
  }

  h->d_stack->ptrs[h->d_stack->current++] = p;
  return p;
}


static void
d_xobs_free_chunk(struct xobs *h, struct d_xobs_stack_chunk *until)
{
  int i;

  while (h->d_stack != until && h->d_stack != 0) {
    struct d_xobs_stack_chunk *p = h->d_stack;
    for (i = p->current - 1; i >= 0; i--) {
      CALL_FREEFUN(h, (struct _xobs_chunk *)p->ptrs[i]);
    }
    h->d_stack = p->prev;
    CALL_FREEFUN(h, (struct _xobs_chunk *)p);
  }
  if (h->d_stack)
    h->d_stack->next = NULL;
}


void
d_xobs_free(LOC_PARAMSPEC, struct xobs *h, const void *ptr)
{
  int i, j;
  struct d_xobs_stack_chunk *p;

  CHECK_UNINIT(h, "xobs_free");

  if (h->d_growing)
    ABORT("xobs_free: growing object detected");

  if (ptr == NULL) {
    d_xobs_free_chunk(h, NULL);
    h->d_stack = (struct d_xobs_stack_chunk *)-1;
    return;
  }

  for (p = h->d_stack; p != NULL; p = p->prev) {
    for (i = p->current - 1; i >= 0; i--) {
      if (p->ptrs[i] == ptr) {
        d_xobs_free_chunk(h, p);
        for (j = p->current - 1; j >= i; j--)
          CALL_FREEFUN(h, (struct _xobs_chunk *)p->ptrs[j]);
        p->current = i;
        return;
      }
    }
  }
  /* PTR is not belong to XOBS!! */
  ABORT("xobs_free: PTR is not valid xobs pointer");
}


void *
d_xobs_copy(LOC_PARAMSPEC, struct xobs *h, const void *ptr, int size)
{
  void *p = d_xobs_alloc_(LOC_PARAMS, "xobs_copy", h, size);
  if (p)
    memcpy(p, ptr, size);
  return p;
}


void *
d_xobs_copy0(LOC_PARAMSPEC, struct xobs *h, const void *ptr, int size)
{
  void *p = d_xobs_alloc_(LOC_PARAMS, "xobs_copy0", h, size + 1);
  if (p) {
    memcpy(p, ptr, size);
    *((unsigned char *)p + size) = '\0';
  }
  return p;
}


int
d_xobs_blank(LOC_PARAMSPEC, struct xobs *h, int size)
{
  return d_xobs_blank_(LOC_PARAMS, "xobs_blank", h, size);
}


static int
d_xobs_blank_(LOC_PARAMSPEC, const char *fname, struct xobs *h, int size)
{
  void *p;

  CHECK_UNINIT(h, fname);

  if (h->d_growing) {
    p = h->d_stack->ptrs[h->d_stack->current - 1];
    size += h->d_growsize;
    p = CALL_DALLOCFUN(h, p, size);
    if (!p) {
      xobs_callfail(h);
      return 0;
    }
    h->d_stack->ptrs[h->d_stack->current - 1] = p;
    h->d_growsize = size;
  }
  else {
    p = d_xobs_alloc(LOC_PARAMS, h, size);
    if (!p)
      return 0;
    h->d_growing = 1;
    h->d_growsize = size;
  }
  return 1;
}


void *
d_xobs_finish(LOC_PARAMSPEC, struct xobs *h)
{
  h->d_growing = 0;
  h->d_growsize = 0;

  if (h->d_stack->current < 0 || h->d_stack->current >= h->d_nelems)
    abort();

  return h->d_stack->ptrs[h->d_stack->current - 1];
}


void *
d_xobs_base(LOC_PARAMSPEC, struct xobs *h)
{
  if (h->d_stack->current < 0 || h->d_stack->current >= h->d_nelems)
    abort();

  return h->d_stack->ptrs[h->d_stack->current - 1];
}


int
d_xobs_object_size(LOC_PARAMSPEC, struct xobs *h)
{
  return h->d_growsize;
}


int
d_xobs_1grow(LOC_PARAMSPEC, struct xobs *h, char c)
{
  char *p;

  if (!d_xobs_blank_(LOC_PARAMS, "xobs_1grow", h, 1))
    return 0;

  p = d_xobs_base(LOC_PARAMS, h);
  p += d_xobs_object_size(LOC_PARAMS, h) - 1;
  *p = c;
  return 1;
}


int
d_xobs_grow(LOC_PARAMSPEC, struct xobs *h, const void *ptr, size_t size)
{
  char *p;

  if (!d_xobs_blank_(LOC_PARAMS, "xobs_grow", h, size))
    return 0;

  p = d_xobs_base(LOC_PARAMS, h);
  p += d_xobs_object_size(LOC_PARAMS, h) - size;
  memcpy(p, ptr, size);
  return 1;
}


int
d_xobs_grow0(LOC_PARAMSPEC, struct xobs *h, const void *ptr, size_t size)
{
  char *p;

  if (!d_xobs_blank_(LOC_PARAMS, "xobs_grow0", h, size + 1))
    return 0;

  p = d_xobs_base(LOC_PARAMS, h);
  p += d_xobs_object_size(LOC_PARAMS, h) - (size + 1);
  memcpy(p, ptr, size);
  *(p + size) = '\0';

  return 1;
}


int
d_xobs_ptr_grow(LOC_PARAMSPEC, struct xobs *h, const void *ptr)
{
  char *p;

  if (!d_xobs_blank_(LOC_PARAMS, "xobs_ptr_grow", h, sizeof(void *)))
    return 0;

  p = d_xobs_base(LOC_PARAMS, h);
  p += d_xobs_object_size(LOC_PARAMS, h) - sizeof(void *);
  *(void **)p = (void *)ptr;
  return 1;
}


int
d_xobs_int_grow(LOC_PARAMSPEC, struct xobs *h, int value)
{
  char *p;

  if (!d_xobs_blank_(LOC_PARAMS, "xobs_ptr_grow", h, sizeof(int)))
    return 0;

  p = d_xobs_base(LOC_PARAMS, h);
  p += d_xobs_object_size(LOC_PARAMS, h) - sizeof(int);
  *(int *)p = value;
  return 1;
}


int
d_xobs_ptr_grow_fast(LOC_PARAMSPEC, struct xobs *h, const void *ptr)
{
  char *p;

  if (h->d_roomsize < sizeof(void *))
    ABORT("xobs_ptr_grow_fast: room is not enough");
  h->d_roomsize -= sizeof(void *);

  if (!d_xobs_blank_(LOC_PARAMS, "xobs_ptr_grow_fast", h, sizeof(void *)))
    return 0;

  p = d_xobs_base(LOC_PARAMS, h);
  p += d_xobs_object_size(LOC_PARAMS, h) - sizeof(void *);
  *(void **)p = (void *)ptr;
  return 1;
}


int
d_xobs_int_grow_fast(LOC_PARAMSPEC, struct xobs *h, int value)
{
  char *p;

  if (h->d_roomsize < sizeof(int))
    ABORT("xobs_int_grow_fast: room is not enough");
  h->d_roomsize -= sizeof(int);

  if (!d_xobs_blank_(LOC_PARAMS, "xobs_int_grow_fast", h, sizeof(int)))
    return 0;

  p = d_xobs_base(LOC_PARAMS, h);
  p += d_xobs_object_size(LOC_PARAMS, h) - sizeof(int);
  *(int *)p = value;
  return 1;
}


int
d_xobs_1grow_fast(LOC_PARAMSPEC, struct xobs *h, char c)
{
  char *p;

  if (h->d_roomsize < 1)
    ABORT("xobs_1grow_fast: room is not enough");
  h->d_roomsize -= sizeof(int);

  if (!d_xobs_blank_(LOC_PARAMS, "xobs_1grow_fast", h, 1))
    return 0;

  p = d_xobs_base(LOC_PARAMS, h);
  p += d_xobs_object_size(LOC_PARAMS, h) - 1;
  *p = c;
  return 1;
}


int
d_xobs_sprintf(LOC_PARAMSPEC, struct xobs *obs, const char *format, ...)
{
  int len;
  va_list ap;
  char *p;

  va_start(ap, format);
  len = vsnprintf(NULL, 0, format, ap);
  va_end(ap);

  p = malloc(len + 1);
  if (!p)
    return -1;
  va_start(ap, format);
  vsnprintf(p, len + 1, format, ap);
  va_end(ap);

  if (d_xobs_grow(LOC_PARAMS, obs, p, len) == 0) {
    free(p);
    return -1;
  }
  free(p);

  return len;
}


#endif  /* DEBUG */

int
xobs_sprintf_(struct xobs *obs, const char *format, ...)
{
  int len;
  va_list ap;
  char *p;

  va_start(ap, format);
  len = vsnprintf(NULL, 0, format, ap);
  va_end(ap);

  xobs_blank(obs, len + 1);
  p = xobs_base(obs) + xobs_object_size(obs) - (len + 1);

  va_start(ap, format);
  vsnprintf(p, len + 1, format, ap);
  va_end(ap);

  obs->next_free--;
  return len;
}


void
xobs_dump(struct xobs *h, FILE *fp)
{
#ifdef DEBUG

#endif  /* DEBUG */
}
