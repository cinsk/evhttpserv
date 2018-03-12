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
 *
 */
#ifndef COMMON_H__
#define COMMON_H__

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

#include <ev.h>

BEGIN_C_DECLS

#ifdef __GNUC__
#ifndef offsetof
#define offsetof(type, member)  __builtin_offsetof(type, member)
#endif
#endif

#define CRLF    "\r\n"
#define CRLFLEN (sizeof(CRLF) - 1)

#define CRLF2    "\r\n\r\n"
#define CRLF2LEN (sizeof(CRLF2) - 1)


#ifndef RCVBUF_SIZE
#define RCVBUF_SIZE     8196
#endif

#ifndef SNDBUF_SIZE
#define SNDBUF_SIZE     8196
#endif

#if 0
struct ev_httpconn;
typedef struct ev_httpconn ev_httpconn;

typedef int (*http_callback)(struct ev_loop *loop,
                             ev_httpconn *hc, int eob,
                             int grpc, char *grpv[], void *data);
#endif  /* 0 */

extern const char *statuscode2str(int statuscode);

END_C_DECLS

#endif /* COMMON_H__ */
