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
#ifndef EVHTTPCONN_H__
#define EVHTTPCONN_H__


#include "common.h"
#include "xobstack.h"
#include "hdrstore.h"
#include "buffer.h"
#include "form.h"

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

enum HTTP_METHOD {
  HM_NONE,
  HM_GET,
  HM_HEAD,
  HM_POST,
  HM_PUT,
  HM_DEBUG_CAT,
  HM_OPTIONS,
  HM_DELETE,
  HM_TRACE,
  HM_UNKNOWN = 100,
};
typedef enum HTTP_METHOD HTTP_METHOD;


#define HTTP_TE_MAX             4

#define HTTP_TE_NONE            0
#define HTTP_TE_IDENTITY        1
#define HTTP_TE_CHUNKED         2
#define HTTP_TE_GZIP            3
#define HTTP_TE_COMPRESS        4
#define HTTP_TE_DEFLATE         5
#define HTTP_TE_UNKNOWN         100

typedef enum {
  HC_INIT,
  HC_RECV_REQ,
  HC_RECV_BODY,
  HC_SEND_RSP,
  HC_SEND_BODY,
} HC_STATE;

struct ev_http;

struct ev_httpconn {
  ev_io io;
  ev_timer timer;

  ev_tstamp r_timeout;
  ev_tstamp w_timeout;

  ev_tstamp acc_time;

  struct ev_http *http;

  HC_STATE state;

  struct xobs hdr_pool; /* 1. keys and values from req_hdrs and rsp_hdrs.
                         * 2. if STATE is HC_SEND_RSP, this will contains
                         *    a growing object, which contains all headers
                         *    from rsp_hdrs. */

  char *hdr_pool_reset;         /* xobs_free()ing this one makes the
                                 * hdr_pool clean. */

  struct hdrstore req_hdrs;

  HTTP_METHOD method;
  char *method_string;
  char *uri;
  char *version;

#ifdef EVHTTP_HANDLE_FORM
  struct form *form;
  struct form form_;
#endif

  char req_te[HTTP_TE_MAX];

  /* When STATE is HC_RECV_BODY,
   * these three members (body_*) record the state of the receiving of
   * request body.  If BODY_CHNK is nonzero, it means that the TE of
   * current request body is 'chunked'.  BODY_SIZE is the size of the
   * current chunk, BODY_REST is the remaining bytes to complete the
   * current chunk.  If BODY_CHNK is zero (i.e. TE is 'identity'),
   * both BODY_SIZE and BODY_REST contain values of the whole body.
   *
   * When STATE is HC_SEND_RSP,
   * BODY_SIZE will contains the size of the RSP_LINE_HDRS, and
   * BODY_REST will contains the remaining bytes of RSP_LINE_HDRS
   * that is not sent yet.  The not-sent-part can be obtained
   * as RSP_LINE_HDRS[BODY_SIZE - BODY_REST] ... RSP_LINE_HDRS[BODY_SIZE] */
  ssize_t body_size;
  ssize_t body_rest;
  int     body_chnk;

  struct buffer ibuf;

  struct hdrstore rsp_hdrs;
  int rsp_code;
  int rsp_disconnect; /* if nonzero, the connection will be disconnected */

  char *rsp_line_hdrs;          /* points the buffer that contains
                                 * response line and response headers
                                 * allocated from HDR_POOL. */

  struct buffer obuf;           /* contains response body */
  int eob;                      /* nonzero means that end of response body. */

  size_t *refcnt;
  int cb_called;                /* number of calls of callback */
};
typedef struct ev_httpconn ev_httpconn;

int ev_httpconn_init(ev_httpconn *hc, struct ev_http *http, int fd, size_t *refcount);
void ev_httpconn_start(struct ev_loop *loop, ev_httpconn *hc);
void ev_httpconn_stop(struct ev_loop *loop, ev_httpconn *hc);

END_C_DECLS

#endif /* EVHTTPCONN_H__ */
