#include <stdlib.h>

#include "openssl/bio.h"
#include "ringbuffer.h"

#include "src/bio.h"
#include "src/common.h"

static int uv_ssl_bio_init(BIO* bio);
static int uv_ssl_bio_destroy(BIO* bio);
static int uv_ssl_bio_write(BIO* bio, const char* data, int len);
static int uv_ssl_bio_read(BIO* bio, char* out, int len);
static long uv_ssl_bio_ctrl(BIO* bio, int cmd, long num, void* ptr);

static BIO_METHOD *method = NULL;

static const BIO_METHOD *create_bio_method()
{
    if (method == NULL) {
        method = BIO_meth_new(BIO_get_new_index(), "uv_ssl SSL BIO");
        if (method == NULL
            || !BIO_meth_set_write(method, uv_ssl_bio_write)
            || !BIO_meth_set_read(method, uv_ssl_bio_read)
//            || !BIO_meth_set_puts(methods, puts)
//            || !BIO_meth_set_gets(methods, gets)
            || !BIO_meth_set_ctrl(method, uv_ssl_bio_ctrl)
            || !BIO_meth_set_create(method, uv_ssl_bio_init)
            || !BIO_meth_set_destroy(method, uv_ssl_bio_destroy))
            return NULL;
    }
    return method;
}


BIO* uv_ssl_bio_new(ringbuffer* buffer) {
  create_bio_method();

  BIO* bio = BIO_new(create_bio_method());
  if (bio == NULL)
    return NULL;

  BIO_set_data(bio, buffer);

  return bio;
}


int uv_ssl_bio_init(BIO* bio) {
  BIO_set_shutdown(bio, 1);
  BIO_set_init(bio, 1);
  BIO_set_fd(bio, -1, 0);

  return 1;
}


int uv_ssl_bio_destroy(BIO* bio) {
  BIO_set_data(bio, NULL);

  return 1;
}


int uv_ssl_bio_write(BIO* bio, const char* data, int len) {
  ringbuffer* buffer;

  BIO_clear_retry_flags(bio);

  buffer = BIO_get_data(bio);

  if (ringbuffer_write_into(buffer, data, len) == 0)
    return len;

  return -1;
}


int uv_ssl_bio_read(BIO* bio, char* out, int len) {
  int r;
  ringbuffer* buffer;

  BIO_clear_retry_flags(bio);

  buffer = BIO_get_data(bio);

  r = (int) ringbuffer_read_into(buffer, out, len);

  if (r == 0) {
    r = BIO_get_fd(bio, 0);
    if (r != 0)
      BIO_set_retry_read(bio);
  }

  return r;
}


long uv_ssl_bio_ctrl(BIO* bio, int cmd, long num, void* ptr) {
  ringbuffer* buffer;
  long ret;

  buffer = BIO_get_data(bio);
  ret = 1;

  switch (cmd) {
    case BIO_CTRL_EOF:
      ret = ringbuffer_is_empty(buffer);
      break;
    case BIO_C_SET_BUF_MEM_EOF_RETURN:
      BIO_set_fd(bio, num, 0);
      break;
    case BIO_CTRL_INFO:
      ret = (long) ringbuffer_size(buffer);
      if (ptr != NULL)
        *(void**)(ptr) = NULL;
      break;
    case BIO_CTRL_RESET:
      CHECK(0, "BIO_CTRL_RESET Unsupported");
      break;
    case BIO_C_SET_BUF_MEM:
      CHECK(0, "BIO_C_SET_BUF_MEM Unsupported");
      break;
    case BIO_C_GET_BUF_MEM_PTR:
      CHECK(0, "BIO_C_GET_BUF_MEM Unsupported");
      break;
    case BIO_CTRL_GET_CLOSE:
      ret = BIO_get_shutdown(bio);
      break;
    case BIO_CTRL_SET_CLOSE:
      BIO_set_shutdown(bio, num);
      break;
    case BIO_CTRL_WPENDING:
      ret = 0;
      break;
    case BIO_CTRL_PENDING:
      ret = (long) ringbuffer_size(buffer);
      break;
    case BIO_CTRL_DUP:
    case BIO_CTRL_FLUSH:
      ret = 1;
      break;
    case BIO_CTRL_PUSH:
    case BIO_CTRL_POP:
    default:
      ret = 0;
      break;
  }
  return ret;
}
