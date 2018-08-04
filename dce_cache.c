/*
 * dce_cache.c
 *
 * Copyright 2001 Paul B. Henson <henson@acm.org>
 *
 * See COPYRIGHT file for details
 *
 */

#include <errno.h>
#include <strings.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dce/sec_login.h>
#include <dce/pgo.h>
#include "dce_cache.h"

/* md5 code borrowed from Apache distribution */

typedef struct {
    unsigned int state[4];		/* state (ABCD) */
    unsigned int count[2];		/* number of bits, modulo 2^64 (lsb first) */
    unsigned char buffer[64];	/* input buffer */
} AP_MD5_CTX;

#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

static unsigned char PADDING[64] =
{
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/* F, G, H and I are basic MD5 functions.
 */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

/* ROTATE_LEFT rotates x left n bits.
 */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
   Rotation is separate from addition to prevent recomputation.
 */
#define FF(a, b, c, d, x, s, ac) { \
 (a) += F ((b), (c), (d)) + (x) + (unsigned int)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define GG(a, b, c, d, x, s, ac) { \
 (a) += G ((b), (c), (d)) + (x) + (unsigned int)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define HH(a, b, c, d, x, s, ac) { \
 (a) += H ((b), (c), (d)) + (x) + (unsigned int)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define II(a, b, c, d, x, s, ac) { \
 (a) += I ((b), (c), (d)) + (x) + (unsigned int)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }

/* Encodes input (unsigned int) into output (unsigned char). Assumes len is
   a multiple of 4.
 */
static void Encode(unsigned char *output, const unsigned int *input, unsigned int len)
{
    unsigned int i, j;
    unsigned int k;

    for (i = 0, j = 0; j < len; i++, j += 4) {
	k = input[i];
	output[j] = (unsigned char) (k & 0xff);
	output[j + 1] = (unsigned char) ((k >> 8) & 0xff);
	output[j + 2] = (unsigned char) ((k >> 16) & 0xff);
	output[j + 3] = (unsigned char) ((k >> 24) & 0xff);
    }
}

/* Decodes input (unsigned char) into output (unsigned int). Assumes len is
 * a multiple of 4.
 */
static void Decode(unsigned int *output, const unsigned char *input, unsigned int len)
{
    unsigned int i, j;

    for (i = 0, j = 0; j < len; i++, j += 4)
	output[i] = ((unsigned int) input[j]) | (((unsigned int) input[j + 1]) << 8) |
	    (((unsigned int) input[j + 2]) << 16) | (((unsigned int) input[j + 3]) << 24);
}


/* MD5 basic transformation. Transforms state based on block. */
static void MD5Transform(unsigned int state[4], const unsigned char block[64])
{
    unsigned int a = state[0], b = state[1], c = state[2], d = state[3], x[16];

    Decode(x, block, 64);

    /* Round 1 */
    FF(a, b, c, d, x[0], S11, 0xd76aa478);	/* 1 */
    FF(d, a, b, c, x[1], S12, 0xe8c7b756);	/* 2 */
    FF(c, d, a, b, x[2], S13, 0x242070db);	/* 3 */
    FF(b, c, d, a, x[3], S14, 0xc1bdceee);	/* 4 */
    FF(a, b, c, d, x[4], S11, 0xf57c0faf);	/* 5 */
    FF(d, a, b, c, x[5], S12, 0x4787c62a);	/* 6 */
    FF(c, d, a, b, x[6], S13, 0xa8304613);	/* 7 */
    FF(b, c, d, a, x[7], S14, 0xfd469501);	/* 8 */
    FF(a, b, c, d, x[8], S11, 0x698098d8);	/* 9 */
    FF(d, a, b, c, x[9], S12, 0x8b44f7af);	/* 10 */
    FF(c, d, a, b, x[10], S13, 0xffff5bb1);	/* 11 */
    FF(b, c, d, a, x[11], S14, 0x895cd7be);	/* 12 */
    FF(a, b, c, d, x[12], S11, 0x6b901122);	/* 13 */
    FF(d, a, b, c, x[13], S12, 0xfd987193);	/* 14 */
    FF(c, d, a, b, x[14], S13, 0xa679438e);	/* 15 */
    FF(b, c, d, a, x[15], S14, 0x49b40821);	/* 16 */

    /* Round 2 */
    GG(a, b, c, d, x[1], S21, 0xf61e2562);	/* 17 */
    GG(d, a, b, c, x[6], S22, 0xc040b340);	/* 18 */
    GG(c, d, a, b, x[11], S23, 0x265e5a51);	/* 19 */
    GG(b, c, d, a, x[0], S24, 0xe9b6c7aa);	/* 20 */
    GG(a, b, c, d, x[5], S21, 0xd62f105d);	/* 21 */
    GG(d, a, b, c, x[10], S22, 0x2441453);	/* 22 */
    GG(c, d, a, b, x[15], S23, 0xd8a1e681);	/* 23 */
    GG(b, c, d, a, x[4], S24, 0xe7d3fbc8);	/* 24 */
    GG(a, b, c, d, x[9], S21, 0x21e1cde6);	/* 25 */
    GG(d, a, b, c, x[14], S22, 0xc33707d6);	/* 26 */
    GG(c, d, a, b, x[3], S23, 0xf4d50d87);	/* 27 */
    GG(b, c, d, a, x[8], S24, 0x455a14ed);	/* 28 */
    GG(a, b, c, d, x[13], S21, 0xa9e3e905);	/* 29 */
    GG(d, a, b, c, x[2], S22, 0xfcefa3f8);	/* 30 */
    GG(c, d, a, b, x[7], S23, 0x676f02d9);	/* 31 */
    GG(b, c, d, a, x[12], S24, 0x8d2a4c8a);	/* 32 */

    /* Round 3 */
    HH(a, b, c, d, x[5], S31, 0xfffa3942);	/* 33 */
    HH(d, a, b, c, x[8], S32, 0x8771f681);	/* 34 */
    HH(c, d, a, b, x[11], S33, 0x6d9d6122);	/* 35 */
    HH(b, c, d, a, x[14], S34, 0xfde5380c);	/* 36 */
    HH(a, b, c, d, x[1], S31, 0xa4beea44);	/* 37 */
    HH(d, a, b, c, x[4], S32, 0x4bdecfa9);	/* 38 */
    HH(c, d, a, b, x[7], S33, 0xf6bb4b60);	/* 39 */
    HH(b, c, d, a, x[10], S34, 0xbebfbc70);	/* 40 */
    HH(a, b, c, d, x[13], S31, 0x289b7ec6);	/* 41 */
    HH(d, a, b, c, x[0], S32, 0xeaa127fa);	/* 42 */
    HH(c, d, a, b, x[3], S33, 0xd4ef3085);	/* 43 */
    HH(b, c, d, a, x[6], S34, 0x4881d05);	/* 44 */
    HH(a, b, c, d, x[9], S31, 0xd9d4d039);	/* 45 */
    HH(d, a, b, c, x[12], S32, 0xe6db99e5);	/* 46 */
    HH(c, d, a, b, x[15], S33, 0x1fa27cf8);	/* 47 */
    HH(b, c, d, a, x[2], S34, 0xc4ac5665);	/* 48 */

    /* Round 4 */
    II(a, b, c, d, x[0], S41, 0xf4292244);	/* 49 */
    II(d, a, b, c, x[7], S42, 0x432aff97);	/* 50 */
    II(c, d, a, b, x[14], S43, 0xab9423a7);	/* 51 */
    II(b, c, d, a, x[5], S44, 0xfc93a039);	/* 52 */
    II(a, b, c, d, x[12], S41, 0x655b59c3);	/* 53 */
    II(d, a, b, c, x[3], S42, 0x8f0ccc92);	/* 54 */
    II(c, d, a, b, x[10], S43, 0xffeff47d);	/* 55 */
    II(b, c, d, a, x[1], S44, 0x85845dd1);	/* 56 */
    II(a, b, c, d, x[8], S41, 0x6fa87e4f);	/* 57 */
    II(d, a, b, c, x[15], S42, 0xfe2ce6e0);	/* 58 */
    II(c, d, a, b, x[6], S43, 0xa3014314);	/* 59 */
    II(b, c, d, a, x[13], S44, 0x4e0811a1);	/* 60 */
    II(a, b, c, d, x[4], S41, 0xf7537e82);	/* 61 */
    II(d, a, b, c, x[11], S42, 0xbd3af235);	/* 62 */
    II(c, d, a, b, x[2], S43, 0x2ad7d2bb);	/* 63 */
    II(b, c, d, a, x[9], S44, 0xeb86d391);	/* 64 */

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;

    /* Zeroize sensitive information. */
    memset(x, 0, sizeof(x));
}

/* MD5 initialization. Begins an MD5 operation, writing a new context.
 */
static void ap_MD5Init(AP_MD5_CTX *context)
{
    context->count[0] = context->count[1] = 0;
    /* Load magic initialization constants. */
    context->state[0] = 0x67452301;
    context->state[1] = 0xefcdab89;
    context->state[2] = 0x98badcfe;
    context->state[3] = 0x10325476;
}

/* MD5 block update operation. Continues an MD5 message-digest
   operation, processing another message block, and updating the
   context.
 */
static void ap_MD5Update(AP_MD5_CTX *context, const unsigned char *input,
			      unsigned int inputLen)
{
    unsigned int i, idx, partLen;

    /* Compute number of bytes mod 64 */
    idx = (unsigned int) ((context->count[0] >> 3) & 0x3F);

    /* Update number of bits */
    if ((context->count[0] += ((unsigned int) inputLen << 3))
	< ((unsigned int) inputLen << 3)) {
	context->count[1]++;
    }
    context->count[1] += (unsigned int) inputLen >> 29;

    partLen = 64 - idx;

    /* Transform as many times as possible. */
    if (inputLen >= partLen) {
	memcpy(&context->buffer[idx], input, partLen);
	MD5Transform(context->state, context->buffer);

	for (i = partLen; i + 63 < inputLen; i += 64) {
	    MD5Transform(context->state, &input[i]);
	}

	idx = 0;
    }
    else {
	i = 0;
    }

    /* Buffer remaining input */
    memcpy(&context->buffer[idx], &input[i], inputLen - i);
}

static void ap_MD5Final(unsigned char digest[16], AP_MD5_CTX *context)
{
    unsigned char bits[8];
    unsigned int idx, padLen;


    /* Save number of bits */
    Encode(bits, context->count, 8);

    /* Pad out to 56 mod 64. */
    idx = (unsigned int) ((context->count[0] >> 3) & 0x3f);
    padLen = (idx < 56) ? (56 - idx) : (120 - idx);
    ap_MD5Update(context, (const unsigned char *)PADDING, padLen);

    /* Append length (before padding) */
    ap_MD5Update(context, (const unsigned char *)bits, 8);

    /* Store state in digest */
    Encode(digest, context->state, 16);

    /* Zeroize sensitive information. */
    memset(context, 0, sizeof(*context));
}

/* end of MD5 code */


static int open_cache_file(uid_t uid, int oflag, char *error_buf, int error_buf_size) {

  char cache_file[MAXPATHLEN];
  int cache_fd;
  int index;
  int status;

  snprintf(cache_file, MAXPATHLEN, "%s/%02d/%d", CACHE_DIR, uid % 100, uid);
  cache_file[MAXPATHLEN - 1] = '\0';

  if ((cache_fd = open(cache_file, oflag, 0600)) == -1) {
    if (errno != ENOENT) {
      snprintf(error_buf, error_buf_size, "failed to open cache file - %d", errno);
      error_buf[error_buf_size - 1] = '\0';
    }

    return -1;
  }

#ifndef ROOT_ONLY
  if (oflag & O_CREAT)
    chown(cache_file, uid, -1);
#endif
  
  index = 0;
  while ((index++ < 5) && ((status = lockf(cache_fd, F_TLOCK, 0)) == -1) && (errno == EAGAIN))
    sleep(1);

  if (status == -1) {
    close(cache_fd);
    snprintf(error_buf,error_buf_size, "failed to lock cache file - %d", errno);
    error_buf[error_buf_size - 1] = '\0';
    return -1;
  }

  return cache_fd;
}

unsigned long dce_cache_authenticate(uid_t uid, char *user, char *password, int credlife, int forwardable, int certify, char *pass_md5, char *error_buf, int error_buf_size) {

  int cache_fd;
  AP_MD5_CTX md5_context;
  unsigned long pag;
  struct stat statbuf;
#ifdef IBM_DCE_ONLY
  struct stat checkstatbuf;
#endif
  char cache_md5[16];
  char import_buf[MAXPATHLEN+5];
  sec_login_handle_t login_context;
  error_status_t status;
  signed32 expiration;
  sec_login_tkt_info_t tkt_info;
  time_t now;

  *error_buf = '\0';
    
  ap_MD5Init(&md5_context);
  ap_MD5Update(&md5_context, (const unsigned char *)password, strlen(password));
  ap_MD5Final(pass_md5, &md5_context);
  
  if ((cache_fd = open_cache_file(uid, O_RDWR, error_buf, error_buf_size)) == -1)
    return 0;
  
  if (credlife == 0)
    credlife = 4 * 60;

  if (fstat(cache_fd, &statbuf) != 0) {
    snprintf(error_buf, error_buf_size, "failed to stat cache file - %d", errno);
    error_buf[error_buf_size-1] = '\0';
    close(cache_fd);
    return 0;
  }

  if (statbuf.st_size != 16 + sizeof(pag)) {
    snprintf(error_buf, error_buf_size, "cache file incorrect size - %d", statbuf.st_size);
    error_buf[error_buf_size-1] = '\0';
    close(cache_fd);
    return 0;
  }

  if (read(cache_fd, cache_md5, 16) != 16) {
    snprintf(error_buf, error_buf_size, "cache file read failed - %d", errno);
    error_buf[error_buf_size-1] = '\0';
    close(cache_fd);
    return 0;
  }

  if (read(cache_fd, &pag, sizeof(pag)) != sizeof(pag)) {
    snprintf(error_buf, error_buf_size, "cache file read failed - %d", errno);
    error_buf[error_buf_size-1] = '\0';
    close(cache_fd);
    return 0;
  }

  close(cache_fd);

  if (memcmp(pass_md5, cache_md5, 16) != 0) {
    snprintf(error_buf, error_buf_size, "password mismatch");
    error_buf[error_buf_size-1] = '\0';
    return 0;
  }

  snprintf(import_buf, MAXPATHLEN+5, "FILE:%s/dcecred_%08x", CREDS_DIR, pag);
  import_buf[MAXPATHLEN+5-1] = '\0';

  sec_login_import_context(MAXPATHLEN+5, import_buf, &login_context, &status);
  if (status) {
    snprintf(error_buf, error_buf_size, "sec_login_import_context failed - %d", status);
    error_buf[error_buf_size-1] = '\0';
    return 0;
  }

  sec_login_get_expiration(login_context, &expiration, &status);
  if (status && (status != sec_login_s_not_certified)) {
    snprintf(error_buf, error_buf_size, "sec_login_get_expiration failed - %d", status);
    error_buf[error_buf_size-1] = '\0';
    return 0;
  }

  now = time(NULL);

  if (now + credlife*60 > expiration) {
    sec_passwd_rec_t pw_entry;
    boolean32 reset_passwd;
    sec_login_auth_src_t auth_src;
    sec_passwd_str_t tmp_pw;
    sec_rgy_cursor_t cursor;
    sec_rgy_member_t member_list[1];
    signed32 num_supplied, num_after, num_before, *groups;

    sec_login_get_groups(login_context, &num_before, &groups, &status);
    if (status && status != sec_login_s_not_certified) {
      snprintf(error_buf, error_buf_size, "sec_login_get_groups failed - %d", status);
      error_buf[error_buf_size-1] = '\0';
      return 0;
    }
    
    sec_rgy_pgo_get_members(sec_rgy_default_handle, sec_rgy_domain_person, user, &cursor, 0, member_list, &num_supplied, &num_after, &status);
    if (status) {
      snprintf(error_buf, error_buf_size, "sec_rgy_pgo_get_members failed - %d", status);
      error_buf[error_buf_size-1] = '\0';
      return 0;
    }

    if (num_before != num_after)
      return 0;
    
    sec_login_refresh_identity(login_context, &status);
    if (status) {
      snprintf(error_buf, error_buf_size, "sec_login_refresh_identity failed - %d", status);
      error_buf[error_buf_size-1] = '\0';
      return 0;
    }
    
    if (forwardable) {
      tkt_info.options = sec_login_tkt_forwardable;
      sec_login_tkt_request_options(login_context, &tkt_info, &status);
    }
    
    pw_entry.version_number = sec_passwd_c_version_none;
    pw_entry.pepper = NULL;
    pw_entry.key.key_type = sec_passwd_plain;
    strncpy( (char *)tmp_pw, password, sec_passwd_str_max_len);
    tmp_pw[sec_passwd_str_max_len] = '\0';
    pw_entry.key.tagged_union.plain = &(tmp_pw[0]);
    
#ifdef IBM_DCE_ONLY
    if (stat(import_buf+5, &statbuf)) {
      snprintf(error_buf, error_buf_size, "stat failed - %d", errno);
      error_buf[error_buf_size-1] = '\0';
      return 0;
    }
#endif

    if (
#ifndef ROOT_ONLY
	getuid() == 0 &&
#endif
	certify)
      sec_login_valid_and_cert_ident(login_context, &pw_entry, &reset_passwd, &auth_src, &status);
    else
      sec_login_validate_identity(login_context, &pw_entry, &reset_passwd, &auth_src, &status);
    
#ifdef IBM_DCE_ONLY
    if (stat(import_buf+5, &checkstatbuf)) {
      snprintf(error_buf, error_buf_size, "stat failed - %d", errno);
      error_buf[error_buf_size-1] = '\0';
      return 0;
    }
    else if (checkstatbuf.st_uid == 0) {
      if (chown(import_buf+5, statbuf.st_uid, statbuf.st_gid)) {
	snprintf(error_buf, error_buf_size, "stat failed - %d", errno);
	error_buf[error_buf_size-1] = '\0';
	return 0;
      }
    }
#endif

    if (status) {
      snprintf(error_buf, error_buf_size, "sec_login_validate_identity failed - %d", status);
      error_buf[error_buf_size-1] = '\0';
      return 0;
    }

  }

  sec_login_release_context(&login_context, &status);

  return pag;
}

int dce_cache_update(uid_t uid, char *pass_md5, unsigned long pag, char *error_buf, int error_buf_size) {

  int cache_fd;

  *error_buf = '\0';
  
  if ((cache_fd = open_cache_file(uid, O_RDWR|O_CREAT, error_buf, error_buf_size)) == -1)
    return 0;

  if (ftruncate(cache_fd, 0) == -1) {
    snprintf(error_buf, error_buf_size, "cache file ftruncate failed - %d", errno);
    error_buf[error_buf_size-1] = '\0';
    close(cache_fd);
    return 0;
  }

  if (write(cache_fd, pass_md5, 16) != 16) {
    snprintf(error_buf, error_buf_size, "cache file write failed - %d", errno);
    error_buf[error_buf_size-1] = '\0';
    close(cache_fd);
    return 0;
  }

  if (write(cache_fd, &pag, sizeof(pag)) != sizeof(pag)) {
    snprintf(error_buf, error_buf_size, "cache file write failed - %d", errno);
    error_buf[error_buf_size-1] = '\0';
    close(cache_fd);
    return 0;
  }

  close(cache_fd);
  return 1;
}
