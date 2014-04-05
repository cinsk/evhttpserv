#ifndef HDRSTORE_H__
#define HDRSTORE_H__

#include "uthash.h"
#include "xobstack.h"


typedef enum {
  HTTP_INIT = 0,                /* initialized for responding */
  HTTP_CONTINUE = 100,
  HTTP_SWITCH,
  HTTP_OK = 200,
  HTTP_CREATED,
  HTTP_ACCEPTED,
  HTTP_NAUTH_INFO,
  HTTP_NO_CONTENT,
  HTTP_RESET_CONTENT,
  HTTP_PARTIAL_CONTENT,
  HTTP_MULTIPLE_CHOICE = 300,
  HTTP_MOVED_PERMANENTLY,
  HTTP_MOVED_TEMPORARILY,
  HTTP_SET_OTHER,
  HTTP_NOT_MODIFIED,
  HTTP_USE_PROXY,
  HTTP_BAD_REQUEST = 400,
  HTTP_UNAUTHORIZED,
  HTTP_PAYMENT_REQUIRED,
  HTTP_FORBIDDEN,
  HTTP_NOT_FOUND,
  HTTP_METHOD_NOT_ALLOWED,
  HTTP_NOT_ACCEPTABLE,
  HTTP_PROXY_AUTH_REQUIRED,
  HTTP_REQUEST_TIMEOUT,
  HTTP_CONFLICT,
  HTTP_GONE,
  HTTP_LENGTH_REQUIRED,
  HTTP_PRECONDITION_FAILED,
  HTTP_REQ_ENTITY_TOO_LARGE,
  HTTP_REQ_URI_TOO_LARGE,
  HTTP_UNSUPPORTED_MEDIA_TYPE,
  HTTP_INTERNAL_SERVER_ERROR = 500,
  HTTP_NOT_IMPLEMENTED,
  HTTP_BAD_GATEWAY,
  HTTP_SERVICE_UNAVAILABLE,
  HTTP_GATEWAY_TIMEOUT,
  HTTP_VERSION_NOT_SUPPORTED,
} httpresponse_t;

struct header {
  const char *name;             /* field-name */
  const char *value;            /* field-value */
  UT_hash_handle hh;
};

struct hdrstore {
  struct xobs *pool;

  struct header *root;
  size_t nheaders;
};

void hdrstore_init(struct hdrstore *store, struct xobs *pool);
void hdrstore_free(struct hdrstore *store);
int hdrstore_set(struct hdrstore *store,
                 const char *key, const char *value);
const char *hdrstore_get(struct hdrstore *store, const char *key);

/*
 * Fill OPOOL with HTTP response line and response headers.
 *
 * If STATUS_CODE is not positive, response line will not be
 * generated.  Generated contents are stored in OPOOL as a growing
 * object, so that you can get the pointer and size using xobs_base()
 * and xobs_object_size().
 *
 * This function returns the number of headers that it generated.
 */
int hdrstore_fill(struct hdrstore *store, struct xobs *opool,
                  const char *version, int status_code);
// char *hdrstore_load(struct hdrstore *store, char *buf, size_t size);

const char *statuscode2str(int statuscode);

#endif /* HDRSTORE_H__ */
