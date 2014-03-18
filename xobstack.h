/* -*-c++-*- */
#ifndef XOBSTACK_H__
#define XOBSTACK_H__

/*
 * xobstack.h - subrotunes used implicitly by object stack macros
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

/* obstack.h - object stack macros
   Copyright (C) 1988-1994,1996-1999,2003,2004,2005,2009
        Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02110-1301, USA.  */

/* Summary:

All the apparent functions defined here are macros. The idea
is that you would use these pre-tested macros to solve a
very specific set of problems, and they would run fast.
Caution: no side-effects in arguments please!! They may be
evaluated MANY times!!

These macros operate a stack of objects.  Each object starts life
small, and may grow to maturity.  (Consider building a word syllable
by syllable.)  An object can move while it is growing.  Once it has
been "finished" it never changes address again.  So the "top of the
stack" is typically an immature growing object, while the rest of the
stack is of mature, fixed size and fixed address objects.

These routines grab large chunks of memory, using a function you
supply, called `obstack_chunk_alloc'.  On occasion, they free chunks,
by calling `obstack_chunk_free'.  You must define them and declare
them before using any obstack macros.

Each independent stack is represented by a `struct obstack'.
Each of the obstack macros expects a pointer to such a structure
as the first argument.

One motivation for this package is the problem of growing char strings
in symbol tables.  Unless you are "fascist pig with a read-only mind"
--Gosper's immortal quote from HAKMEM item 154, out of context--you
would not like to put any arbitrary upper limit on the length of your
symbols.

In practice this often means you will build many short symbols and a
few long symbols.  At the time you are reading a symbol you don't know
how long it is.  One traditional method is to read a symbol into a
buffer, realloc()ating the buffer every time you try to read a symbol
that is longer than the buffer.  This is beaut, but you still will
want to copy the symbol from the buffer to a more permanent
symbol-table entry say about half the time.

With obstacks, you can work differently.  Use one obstack for all symbol
names.  As you read a symbol, grow the name in the obstack gradually.
When the name is complete, finalize it.  Then, if the symbol exists already,
free the newly read name.

The way we do this is to take a large chunk, allocating memory from
low addresses.  When you want to build a symbol in the chunk you just
add chars above the current "high water mark" in the chunk.  When you
have finished adding chars, because you got to the end of the symbol,
you know how long the chars are, and you can create a new object.
Mostly the chars will not burst over the highest address of the chunk,
because you would typically expect a chunk to be (say) 100 times as
long as an average object.

In case that isn't clear, when we have enough chars to make up
the object, THEY ARE ALREADY CONTIGUOUS IN THE CHUNK (guaranteed)
so we just point to it where it lies.  No moving of chars is
needed and this is the second win: potentially long strings need
never be explicitly shuffled. Once an object is formed, it does not
change its address during its lifetime.

When the chars burst over a chunk boundary, we allocate a larger
chunk, and then copy the partly formed object from the end of the old
chunk to the beginning of the new larger chunk.  We then carry on
accreting characters to the end of the object as we normally would.

A special macro is provided to add a single char at a time to a
growing object.  This allows the use of register variables, which
break the ordinary 'growth' macro.

Summary:
        We allocate large chunks.
        We carve out one object at a time from the current chunk.
        Once carved, an object never moves.
        We are free to append data of any size to the currently
          growing object.
        Exactly one object is growing in an obstack at any one time.
        You can run one obstack per control block.
        You may have as many control blocks as you dare.
        Because of the way we do it, you can `unwind' an obstack
          back to a previous state. (You may remove objects much
          as you would with a stack.)
*/

/*
 * Copied from glibc-2.14.1, modified for Darwin compilation -- cinsk
 */

/* Don't do the contents of this file more than once.  */

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


#ifndef xobs_chunk_alloc
# ifdef __cplusplus
#  include <cstdlib>
#  define xobs_chunk_alloc     std::malloc
#  define xobs_chunk_free      std::free
# else
#  include <stdlib.h>
#  define xobs_chunk_alloc     malloc
#  define xobs_chunk_free      free
# endif  /* __cplusplus */
#endif


BEGIN_C_DECLS


/* We need the type of a pointer subtraction.  If __PTRDIFF_TYPE__ is
   defined, as with GNU C, use that; that way we don't pollute the
   namespace with <stddef.h>'s symbols.  Otherwise, include <stddef.h>
   and use ptrdiff_t.  */

#ifdef __PTRDIFF_TYPE__
# define PTR_INT_TYPE __PTRDIFF_TYPE__
#else
# include <stddef.h>
# define PTR_INT_TYPE ptrdiff_t
#endif

/* If B is the base of an object addressed by P, return the result of
   aligning P to the next multiple of A + 1.  B and P must be of type
   char *.  A + 1 must be a power of 2.  */

#ifndef __BPTR_ALIGN
#define __BPTR_ALIGN(B, P, A) ((B) + (((P) - (B) + (A)) & ~(A)))
#endif

/* Similiar to _BPTR_ALIGN (B, P, A), except optimize the common case
   where pointers can be converted to integers, aligned as integers,
   and converted back again.  If PTR_INT_TYPE is narrower than a
   pointer (e.g., the AS/400), play it safe and compute the alignment
   relative to B.  Otherwise, use the faster strategy of computing the
   alignment relative to 0.  */
#ifndef __PTR_ALIGN
#define __PTR_ALIGN(B, P, A)                                                \
  __BPTR_ALIGN (sizeof (PTR_INT_TYPE) < sizeof (void *) ? (B) : (char *) 0, \
                P, A)
#endif

#include <string.h>

struct _xobs_chunk              /* Lives at front of each chunk. */
{
  char  *limit;                 /* 1 past end of this chunk */
  struct _xobs_chunk *prev;     /* address of prior chunk or NULL */
  char  contents[4];            /* objects begin here */
};

struct d_xobs_stack_chunk
{
  struct d_xobs_stack_chunk *prev;
  struct d_xobs_stack_chunk *next;
  int current;
  void *ptrs[1];
};

struct xobs          /* control current object in current chunk */
{
  long  chunk_size;             /* preferred size to allocate chunks in */
  struct _xobs_chunk *chunk;    /* address of current struct xobs_chunk */
  char  *object_base;           /* address of object we are building */
  char  *next_free;             /* where to add next char to current object */
  char  *chunk_limit;           /* address of char after current chunk */
  union
  {
    PTR_INT_TYPE tempint;
    void *tempptr;
  } temp;                       /* Temporary for some macros.  */
  int   alignment_mask;         /* Mask of alignment for each object. */
  /* These prototypes vary based on `use_extra_arg', and we use
     casts to the prototypeless function type in all assignments,
     but having prototypes here quiets -Wstrict-prototypes.  */
  struct _xobs_chunk *(*chunkfun) (void *, long);
  void (*freefun) (void *, struct _xobs_chunk *);
  void (*failfun) (struct xobs *self);

  void *extra_arg;              /* first arg for chunk alloc/dealloc funcs */

#ifdef DEBUG
  size_t d_nelems;
  struct d_xobs_stack_chunk *d_stack;
  size_t d_growsize;
  size_t d_roomsize;

  void *(*dallocfun) (void *, size_t);

  unsigned d_growing:1;
#endif /* DEBUG */

  unsigned use_extra_arg:1;     /* chunk alloc/dealloc funcs take extra arg */
  unsigned maybe_empty_object:1;/* There is a possibility that the current
                                   chunk contains a zero-length object.  This
                                   prevents freeing the chunk if we allocate
                                   a bigger chunk to replace it. */
#if 0
  /* I don't need compatibility with obstack -- cinsk */
  unsigned alloc_failed:1;      /* No longer used, as we now call the failed
                                   handler on error, but retained for binary
                                   compatibility.  */
#endif  /* 0 */
};

/* Declare the external functions we use; they are in xobs.c.  */

/* Unlike GNU obstack, these three functions will return 1 on success,
 * and will return 0 on failure.
 *
 * Note that all macros or function that calls these functions are
 * also returning 1 on success and returning 0 on failure. --cinsk */
extern int _xobs_newchunk (struct xobs *, int);
extern int _xobs_begin (struct xobs *, int, int,
                            void *(*) (long), void (*) (void *));
extern int _xobs_begin_1 (struct xobs *, int, int,
                             void *(*) (void *, long),
                             void (*) (void *, void *), void *);

extern int xobs_sprintf_(struct xobs *obs, const char *format, ...);


extern int _xobs_memory_used (struct xobs *);
void xobs_free (struct xobs *xobs__, void *block__);


/* Error handler called when `xobs_chunk_alloc' failed to allocate
   more memory.  This can be set to a user defined function which
   should either abort gracefully or use longjump - but shouldn't
   return.  The default action is to print a message and abort.  */
extern void (*xobs_alloc_failed_handler) (void);

/* Exit value used when `print_and_abort' is used.  */
extern int xobs_exit_failure;

/* Pointer to beginning of object being allocated or to be allocated next.
   Note that this might not be the final address of the object
   because a new chunk might be needed to hold the final size.  */

#define xobs_base(h) ((void *) ((h)->object_base))

/* Size for allocating ordinary chunks.  */

#define xobs_chunk_size(h) ((h)->chunk_size)

/* Pointer to next byte not yet allocated in current chunk.  */

#define xobs_next_free(h)    ((h)->next_free)

/* Mask specifying low bits that should be clear in address of an object.  */

#define xobs_alignment_mask(h) ((h)->alignment_mask)

#ifndef DEBUG
/* To prevent prototype warnings provide complete argument list.  */
#define xobs_init(h)                                         \
  _xobs_begin ((h), 0, 0,                                    \
               (void *(*) (long)) xobs_chunk_alloc,          \
               (void (*) (void *)) xobs_chunk_free)

#define xobs_begin(h, size)                                  \
  _xobs_begin ((h), (size), 0,                               \
               (void *(*) (long)) xobs_chunk_alloc,          \
               (void (*) (void *)) xobs_chunk_free)

#define xobs_specify_allocation(h, size, alignment, chunkfun, freefun)  \
  _xobs_begin ((h), (size), (alignment),                                \
               (void *(*) (long)) (chunkfun),                           \
               (void (*) (void *)) (freefun))

#define xobs_specify_allocation_with_arg(h, size, alignment, chunkfun, freefun, arg) \
  _xobs_begin_1 ((h), (size), (alignment),                              \
                    (void *(*) (void *, long)) (chunkfun),              \
                    (void (*) (void *, void *)) (freefun), (arg))
#else  /* DEBUG */
#define xobs_init(h)                                                    \
  d_xobs_begin(__FILE__, __LINE__, h, 0, 0,                             \
               (void *(*) (long)) malloc,                               \
               (void (*) (void *)) free, realloc)

#define xobs_begin(h, size)                                             \
  d_xobs_begin(__FILE__, __LINE__, h, size, 0,                          \
               (void *(*) (long)) malloc,                               \
               (void (*) (void *)) free, realloc)

#define xobs_specify_allocation(h, size, alignment, chunkfun, freefun)  \
  d_xobs_begin(__FILE__, __LINE__, h, size, alignment,                  \
               (void *(*) (long)) malloc,                               \
               (void (*) (void *)) free, realloc)

#define xobs_specify_allocation_with_arg(h, size, alignment, chunkfun, freefun, arg) \
  d_xobs_begin(__FILE__, __LINE__, h, size, alignment,                  \
               (void *(*) (long)) malloc,                               \
               (void (*) (void *)) free, realloc)

#endif /* DEBUG */

#define xobs_chunkfun(h, newchunkfun) \
  ((h) -> chunkfun = (struct _xobs_chunk *(*)(void *, long)) (newchunkfun))

#define xobs_freefun(h, newfreefun) \
  ((h) -> freefun = (void (*)(void *, struct _xobs_chunk *)) (newfreefun))


#define xobs_failproc(h, err)  do {             \
    if (err) xobs_callfail(h);                  \
  } while (0)

#define xobs_callfail(h)  do {                  \
    if ((h)->failfun)                           \
      (*(h)->failfun)(h);                       \
    else if (xobs_alloc_failed_handler)         \
      (*xobs_alloc_failed_handler)();           \
  } while (0)


#define xobs_1grow_fast(h,achar) (*((h)->next_free)++ = (achar))

#define xobs_blank_fast(h,n) ((h)->next_free += (n))

#define xobs_memory_used(h) _xobs_memory_used (h)

/*
 * xobs_sprintf(o, format, ...)
 *
 * Grow OBSTACK with the string built from printf(3)-like arguments.
 * Note that this does not add '\0' in the end of the string.  If you
 * want to build zero-terminated striing, use xobs_sprintf0 or add
 * '\0' using xobs_1grow.
 *
 * On success, it returns the length of the string it added.
 * Otherwise, It returns -1 (e.g. allocation failure).
 */
#define xobs_sprintf(o, fmt, ...)  xobs_sprintf_((o), (fmt), ## __VA_ARGS__)


#if defined __GNUC__ && defined __STDC__ && __STDC__
/* NextStep 2.0 cc is really gcc 1.93 but it defines __GNUC__ = 2 and
   does not implement __extension__.  But that compiler doesn't define
   __GNUC_MINOR__.  */
# if __GNUC__ < 2 || (__NeXT__ && !__GNUC_MINOR__)
#  define __extension__
# endif

/* For GNU C, if not -traditional,
   we can define these macros to compute all args only once
   without using a global variable.
   Also, we can avoid using the `temp' slot, to make faster code.  */

# define xobs_object_size(OBSTACK)                                      \
  __extension__                                                         \
  ({ struct xobs const *__o = (OBSTACK);                                \
     (unsigned) (__o->next_free - __o->object_base); })

# define xobs_room(OBSTACK)                                             \
  __extension__                                                         \
  ({ struct xobs const *__o = (OBSTACK);                                \
     (unsigned) (__o->chunk_limit - __o->next_free); })

# define xobs_make_room(OBSTACK,length)                                 \
__extension__                                                           \
({ struct xobs *__o = (OBSTACK);                                        \
   int __len = (length);                                                \
   int ___ok = 1;                                                       \
   if (__o->chunk_limit - __o->next_free < __len)                       \
     ___ok = _xobs_newchunk (__o, __len);                               \
   xobs_failproc(__o, !___ok);                                          \
   ___ok; })

# define xobs_empty_p(OBSTACK)                                          \
  __extension__                                                         \
  ({ struct xobs const *__o = (OBSTACK);                                \
     (__o->chunk->prev == 0                                             \
      && __o->next_free == __PTR_ALIGN ((char *) __o->chunk,            \
                                        __o->chunk->contents,           \
                                        __o->alignment_mask)); })

# define xobs_grow(OBSTACK,where,length)                                \
__extension__                                                           \
({ struct xobs *__o = (OBSTACK);                                        \
   int __len = (length);                                                \
   int ___ok = 1;                                                       \
   if (__o->next_free + __len > __o->chunk_limit)                       \
     ___ok = _xobs_newchunk (__o, __len);                               \
   if (___ok) {                                                         \
     memcpy (__o->next_free, where, __len);                             \
     __o->next_free += __len;                                           \
   }                                                                    \
   else                                                                 \
     xobs_callfail(__o);                                                \
   ___ok; })

# define xobs_grow0(OBSTACK,where,length)                               \
__extension__                                                           \
({ struct xobs *__o = (OBSTACK);                                        \
   int __len = (length);                                                \
   int ___ok = 1;                                                       \
   if (__o->next_free + __len + 1 > __o->chunk_limit)                   \
     ___ok = _xobs_newchunk (__o, __len + 1);                           \
   if (___ok) {                                                         \
     memcpy (__o->next_free, where, __len);                             \
     __o->next_free += __len;                                           \
     *(__o->next_free)++ = 0;                                           \
   }                                                                    \
   else                                                                 \
     xobs_callfail(__o);                                                \
   ___ok; })

# define xobs_1grow(OBSTACK,datum)                                      \
__extension__                                                           \
({ struct xobs *__o = (OBSTACK);                                        \
   int ___ok = 1;                                                       \
   if (__o->next_free + 1 > __o->chunk_limit)                           \
     ___ok = _xobs_newchunk (__o, 1);                                   \
   if (___ok)                                                           \
     xobs_1grow_fast (__o, datum);                                      \
   else                                                                 \
     xobs_callfail(__o);                                                \
   ___ok; })

/* These assume that the xobs alignment is good enough for pointers
   or ints, and that the data added so far to the current object
   shares that much alignment.  */

# define xobs_ptr_grow(OBSTACK,datum)                                   \
__extension__                                                           \
({ struct xobs *__o = (OBSTACK);                                        \
   int ___ok = 1;                                                       \
   if (__o->next_free + sizeof (void *) > __o->chunk_limit)             \
     ___ok = _xobs_newchunk (__o, sizeof (void *));                     \
   if (___ok)                                                           \
     xobs_ptr_grow_fast (__o, datum);                                   \
   else                                                                 \
     xobs_callfail(__o);                                                \
   ___ok; })

# define xobs_int_grow(OBSTACK,datum)                                   \
__extension__                                                           \
({ struct xobs *__o = (OBSTACK);                                        \
   int ___ok = 1;                                                       \
   if (__o->next_free + sizeof (int) > __o->chunk_limit)                \
     ___ok = _xobs_newchunk (__o, sizeof (int));                        \
   if (___ok)                                                           \
     xobs_int_grow_fast (__o, datum);                                   \
   else                                                                 \
     xobs_callfail(__o);                                                \
   ___ok; })

# define xobs_ptr_grow_fast(OBSTACK,aptr)                               \
__extension__                                                           \
({ struct xobs *__o1 = (OBSTACK);                                       \
   *(const void **) __o1->next_free = (aptr);                           \
   __o1->next_free += sizeof (const void *);                            \
   (void) 0; })

# define xobs_int_grow_fast(OBSTACK,aint)                               \
__extension__                                                           \
({ struct xobs *__o1 = (OBSTACK);                                       \
   *(int *) __o1->next_free = (aint);                                   \
   __o1->next_free += sizeof (int);                                     \
   (void) 0; })

# define xobs_blank(OBSTACK,length)                                     \
__extension__                                                           \
({ struct xobs *__o = (OBSTACK);                                        \
   int __len = (length);                                                \
   int ___ok = 1;                                                       \
   if (__o->chunk_limit - __o->next_free < __len)                       \
     ___ok = _xobs_newchunk (__o, __len);                               \
   if (___ok)                                                           \
     xobs_blank_fast (__o, __len);                                      \
   else                                                                 \
     xobs_callfail(__o);                                                \
   ___ok; })

# define xobs_alloc(OBSTACK,length)                                     \
__extension__                                                           \
({ struct xobs *__h = (OBSTACK);                                        \
   void *__p = NULL;                                                    \
   if (xobs_blank (__h, (length)))                                      \
     __p = xobs_finish (__h);                                           \
   __p; })

# define xobs_copy(OBSTACK,where,length)                                \
__extension__                                                           \
({ struct xobs *__h = (OBSTACK);                                        \
   void *__p = NULL;                                                    \
   if (xobs_grow (__h, (where), (length)))                              \
     __p = xobs_finish (__h);                                           \
   __p; })

# define xobs_copy0(OBSTACK,where,length)                               \
__extension__                                                           \
({ struct xobs *__h = (OBSTACK);                                        \
   void *__p = NULL; \
   if (xobs_grow0 (__h, (where), (length)))                             \
     __p = xobs_finish (__h);                                           \
   __p; })

/* The local variable is named __o1 to avoid a name conflict
   when xobs_blank is called.  */
# define xobs_finish(OBSTACK)                                           \
__extension__                                                           \
({ struct xobs *__o1 = (OBSTACK);                                       \
   void *__value = (void *) __o1->object_base;                          \
   if (__o1->next_free == __value)                                      \
     __o1->maybe_empty_object = 1;                                      \
   __o1->next_free                                                      \
     = __PTR_ALIGN (__o1->object_base, __o1->next_free,                 \
                    __o1->alignment_mask);                              \
   if (__o1->next_free - (char *)__o1->chunk                            \
       > __o1->chunk_limit - (char *)__o1->chunk)                       \
     __o1->next_free = __o1->chunk_limit;                               \
   __o1->object_base = __o1->next_free;                                 \
   __value; })

# define xobs_free(OBSTACK, OBJ)                                        \
__extension__                                                           \
({ struct xobs *__o = (OBSTACK);                                        \
   void *__obj = (OBJ);                                                 \
   if (__obj > (void *)__o->chunk && __obj < (void *)__o->chunk_limit)  \
     __o->next_free = __o->object_base = (char *)__obj;                 \
   else (xobs_free) (__o, __obj); })

// TODO: xobs_sprintf0() should revert XOBS state if xobs_1grow() failed.
#define xobs_sprintf0(o, fmt, ...)      ({              \
      int len = xobs_sprintf((o), (fmt), __VA_ARGS__);  \
      if (len >= 0) {                                   \
        if (xobs_1grow((o), '\0') != 0)                 \
          len += 1;                                     \
        else                                            \
          len = -1;                                     \
      }                                                 \
      len; })


#else /* not __GNUC__ or not __STDC__ */

/* Authentic obstack is designed to work with non GNU C,
 * by providing interface implemented via pure C macros.
 *
 * So, it is very difficult to provide a return status for some
 * operations.  Since my personal purpose is mostly with the modern
 * compilers, it is much easier to implement the interface using
 * inline functions. -- cinsk */

# define xobs_object_size(h) \
 (unsigned) ((h)->next_free - (h)->object_base)

# define xobs_room(h)                \
 (unsigned) ((h)->chunk_limit - (h)->next_free)

# define xobs_empty_p(h) \
 ((h)->chunk->prev == 0                                                 \
  && (h)->next_free == __PTR_ALIGN ((char *) (h)->chunk,                \
                                    (h)->chunk->contents,               \
                                    (h)->alignment_mask))

/* Note that the call to _xobs_newchunk is enclosed in (..., 0)
   so that we can avoid having void expressions
   in the arms of the conditional expression.
   Casting the third operand to void was tried before,
   but some compilers won't accept it.  */

# define xobs_make_room(h,length)                                       \
( (h)->temp.tempint = (length),                                         \
  (((h)->next_free + (h)->temp.tempint > (h)->chunk_limit)              \
   ? (_xobs_newchunk ((h), (h)->temp.tempint), 0) : 0))

# define xobs_grow(h,where,length)                                      \
( (h)->temp.tempint = (length),                                         \
  (((h)->next_free + (h)->temp.tempint > (h)->chunk_limit)              \
   ? (_xobs_newchunk ((h), (h)->temp.tempint), 0) : 0),                 \
  memcpy ((h)->next_free, where, (h)->temp.tempint),                    \
  (h)->next_free += (h)->temp.tempint)

# define xobs_grow0(h,where,length)                                     \
( (h)->temp.tempint = (length),                                         \
  (((h)->next_free + (h)->temp.tempint + 1 > (h)->chunk_limit)          \
   ? (_xobs_newchunk ((h), (h)->temp.tempint + 1), 0) : 0),             \
  memcpy ((h)->next_free, where, (h)->temp.tempint),                    \
  (h)->next_free += (h)->temp.tempint,                                  \
  *((h)->next_free)++ = 0)

# define xobs_1grow(h,datum)                                            \
( (((h)->next_free + 1 > (h)->chunk_limit)                              \
   ? (_xobs_newchunk ((h), 1), 0) : 0),                                 \
  xobs_1grow_fast (h, datum))

# define xobs_ptr_grow(h,datum)                                         \
( (((h)->next_free + sizeof (char *) > (h)->chunk_limit)                \
   ? (_xobs_newchunk ((h), sizeof (char *)), 0) : 0),                   \
  xobs_ptr_grow_fast (h, datum))

# define xobs_int_grow(h,datum)                                         \
( (((h)->next_free + sizeof (int) > (h)->chunk_limit)                   \
   ? (_xobs_newchunk ((h), sizeof (int)), 0) : 0),                      \
  xobs_int_grow_fast (h, datum))

# define xobs_ptr_grow_fast(h,aptr)                                     \
  (((const void **) ((h)->next_free += sizeof (void *)))[-1] = (aptr))

# define xobs_int_grow_fast(h,aint)                                     \
  (((int *) ((h)->next_free += sizeof (int)))[-1] = (aint))

# define xobs_blank(h,length)                                           \
( (h)->temp.tempint = (length),                                         \
  (((h)->chunk_limit - (h)->next_free < (h)->temp.tempint)              \
   ? (_xobs_newchunk ((h), (h)->temp.tempint), 0) : 0),                 \
  xobs_blank_fast (h, (h)->temp.tempint))

# define xobs_alloc(h,length)                                           \
 (xobs_blank ((h), (length)), xobs_finish ((h)))

# define xobs_copy(h,where,length)                                      \
 (xobs_grow ((h), (where), (length)), xobs_finish ((h)))

# define xobs_copy0(h,where,length)                                     \
 (xobs_grow0 ((h), (where), (length)), xobs_finish ((h)))

# define xobs_finish(h)                                                 \
( ((h)->next_free == (h)->object_base                                   \
   ? (((h)->maybe_empty_object = 1), 0)                                 \
   : 0),                                                                \
  (h)->temp.tempptr = (h)->object_base,                                 \
  (h)->next_free                                                        \
    = __PTR_ALIGN ((h)->object_base, (h)->next_free,                    \
                   (h)->alignment_mask),                                \
  (((h)->next_free - (char *) (h)->chunk                                \
    > (h)->chunk_limit - (char *) (h)->chunk)                           \
   ? ((h)->next_free = (h)->chunk_limit) : 0),                          \
  (h)->object_base = (h)->next_free,                                    \
  (h)->temp.tempptr)

# define xobs_free(h,obj)                                               \
( (h)->temp.tempint = (char *) (obj) - (char *) (h)->chunk,             \
  ((((h)->temp.tempint > 0                                              \
    && (h)->temp.tempint < (h)->chunk_limit - (char *) (h)->chunk))     \
   ? (int) ((h)->next_free = (h)->object_base                           \
            = (h)->temp.tempint + (char *) (h)->chunk)                  \
   : (((xobs_free) ((h), (h)->temp.tempint + (char *) (h)->chunk), 0), 0)))

// TODO: implmenet xobs_sprintf0 without using ({...})
#define xobs_sprintf0(o, fmt, ...)

#endif /* not __GNUC__ or not __STDC__ */

#define xobs_grow_literal(o, src)       xobs_grow((o), (src), sizeof(src) - 1)
#define xobs_grow_literal0(o, src)      xobs_grow((o), (src), sizeof(src))

#ifdef DEBUG
#undef xobs_alloc
#define xobs_alloc(h, s)        d_xobs_alloc(__FILE__, __LINE__, (h), (s))
#undef xobs_free
#define xobs_free(h, p)         d_xobs_free(__FILE__, __LINE__, (h), (p))
#undef xobs_copy
#define xobs_copy(h, p, s)      d_xobs_copy(__FiLE__, __LINE__, (h), (p), (s))
#undef xobs_copy0
#define xobs_copy0(h, p, s)     d_xobs_copy0(__FILE__, __LINE__, (h), (p), (s))
#undef xobs_blank
#define xobs_blank(h, s)        d_xobs_blank(__FILE__, __LINE__, (h), (s))
#undef xobs_finish
#define xobs_finish(h)          d_xobs_finish(__FILE__, __LINE__, h)
#undef xobs_base
#define xobs_base(h)            d_xobs_base(__FILE__, __LINE__, h)
#undef xobs_object_size
#define xobs_object_size(h)     d_xobs_object_size(__FILE__, __LINE__, h)
#undef xobs_1grow
#define xobs_1grow(h, c)        d_xobs_1grow(__FILE__, __LINE__, (h), (c))
#undef xobs_grow
#define xobs_grow(h, p, s)      d_xobs_grow(__FILE__, __LINE__, (h), (p), (s))
#undef xobs_grow0
#define xobs_grow0(h, p, s)     d_xobs_grow0(__FILE__, __LINE__, (h), (p), (s))
#undef xobs_room
#define xobs_room(h)            ((h)->d_roomsize)
#undef xobs_make_room
#define xobs_make_room(h, s)    do { (h)->d_roomsize = s; } while (0)
#undef xobs_ptr_grow
#define xobs_ptr_grow(h, p)     d_xobs_ptr_grow((h), (p))
#undef xobs_int_grow
#define xobs_int_grow(h, v)     d_xobs_int_grow((h), (v))
#undef xobs_ptr_grow_fast
#define xobs_ptr_grow_fast(h, p)        d_xobs_ptr_grow_fast((h), (p))
#undef xobs_int_grow_fast
#define xobs_int_grow_fast(h, v)        d_xobs_int_grow_fast((h), (v))
#undef xobs_1grow_fast
#define xobs_1grow_fast(h, c)   d_xobs_1grow_fast((h), (c))
#undef xobs_sprintf
#define xobs_sprintf(h, f, ...) d_xobs_sprintf(__FILE__, __LINE__, (h), (f), __VA_ARGS__)

int d_xobs_begin(const char *file, int lineno,
                 struct xobs *h, int size, int alignment,
                 void *(*chunkfun) (long),
                 void (*freefun) (void *),
                 void *(*dallocfun) (void *, size_t));

void *d_xobs_alloc(const char *file, int lineno, struct xobs *h, int size);
void d_xobs_free(const char *file, int lineno, struct xobs *h, const void *ptr);

int d_xobs_blank(const char *file, int lineno, struct xobs *h, int size);
void *d_xobs_finish(const char *file, int lineno, struct xobs *h);
void *d_xobs_object_base(const char *file, int lineno, struct xobs *stack);
int d_xobs_object_size(const char *file, int lineno, struct xobs *h);
int d_xobs_1grow(const char *, int, struct xobs *h, char c);
int d_xobs_grow(const char *, int, struct xobs *h, const void *ptr, size_t size);
int d_xobs_grow0(const char *, int, struct xobs *h, const void *ptr, size_t size);
int d_xobs_ptr_grow(const char *, int, struct xobs *h, const void *ptr);
int d_xobs_int_grow(const char *, int, struct xobs *h, int value);
int d_xobs_ptr_grow_fast(const char *, int, struct xobs *h, const void *ptr);
int d_xobs_int_grow_fast(const char *, int, struct xobs *h, int value);
int d_xobs_1grow_fast(const char *, int, struct xobs *h, char c);
void *d_xobs_base(const char *, int, struct xobs *h);
int d_xobs_sprintf(const char *, int,
                   struct xobs *h, const char *format, ...);
#endif  /* DEBUG */

END_C_DECLS

#ifdef __cplusplus
#include <new>

class XOBS {
  xobs pool;

public:
  XOBS() {
    if (!xobs_init(&pool))
      throw std::bad_alloc();
  }

  XOBS(size_t size) {
    if (!xobs_begin(&pool, size))
      throw std::bad_alloc();
  }

  ~XOBS() {
    xobs_free(&pool, 0);
  }

  void *alloc(size_t sz) {
    void *p = xobs_alloc(&pool, sz);
    if (!p)
      throw std::bad_alloc();
    return p;
  }

  void *copy(const void *src, size_t sz) {
    void *p = xobs_copy(&pool, src, sz);
    if (!p)
      throw std::bad_alloc();
    return p;
  }

  void *copy0(const void *src, size_t sz) {
    void *p = xobs_copy0(&pool, src, sz);
    if (!p)
      throw std::bad_alloc();
    return p;
  }

  void free(const void *src = 0) {
    xobs_free(&pool, (void *)src);
  }

  void blank(size_t sz) {
    if (!xobs_blank(&pool, sz))
      throw std::bad_alloc();
  }

  void grow(const void *src, size_t sz) {
    if (!xobs_grow(&pool, src, sz))
      throw std::bad_alloc();
  }

  void grow0(const void *src, size_t sz) {
    if (!xobs_grow0(&pool, src, sz))
      throw std::bad_alloc();
  }

  template <typename T>
  void grow(T val) {
    if (!xobs_grow(&pool, &val, sizeof(val)))
      throw std::bad_alloc();
  }

  void *finish(void) {
    return xobs_finish(&pool);
  }

  size_t object_size() {
    return xobs_object_size(&pool);
  }

  size_t room(void) {
    return xobs_room(&pool);
  }

  template <typename T>
  void grow_fast(const T &val) {
    *(T *)pool.next_free = val;
    pool.next_free += sizeof(T);
  }

  void blank_fast(size_t sz) {
    xobs_blank_fast(&pool, sz);
  }

  void *base(void) {
    return xobs_base(&pool);
  }

  void *next_free(void) {
    return xobs_next_free(&pool);
  }

  int alignment_mask(void) {
    return xobs_alignment_mask(&pool);
  }

  int chunk_size() {
    return xobs_chunk_size(&pool);
  }


  template <typename T>
  void del(T *p) {
    if (p) {
      p->~T();
      free(p);
    }
  }
};


void *
operator new(size_t sz, XOBS &obs)
{
  return obs.alloc(sz);
}

#endif  /* __cplusplus */

#endif  /* XOBSTACK_H__ */
