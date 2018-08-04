/*
 * pam_dce_cache.c
 *
 * Copyright 2001 Paul B. Henson <henson@acm.org>
 *
 * See COPYRIGHT file for details
 *
 */

#define CACHE_DIR "/opt/dcelocal/var/security/cache"
#define CREDS_DIR "/opt/dcelocal/var/security/creds"

#include <errno.h>
#include <syslog.h>
#include <strings.h>
#include <stdlib.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <dce/sec_login.h>

static int acquire_password(pam_handle_t *pamh, char **password)
{
  struct pam_conv *pam_convp;
  struct pam_message message;
  struct pam_message *message_p = &message;
  struct pam_response *response;
  int status;

  if ((status = pam_get_item(pamh, PAM_CONV, (void**) &pam_convp)) != PAM_SUCCESS) {
    syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.acquire_password - failed to retrieve pam_convp: %d", status);
    return status;
  }

  message_p->msg_style = PAM_PROMPT_ECHO_OFF;
  message_p->msg = "DCE Password: ";

  if ((status = pam_convp->conv(1, &message_p, &response, NULL)) != PAM_SUCCESS) {
    syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.acquire_password - pam_convp call failed: %d", status);
    return status;
  }

  if (response->resp == NULL) {
    syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.acquire_password - pam_convp call returned null password");
    status = PAM_AUTH_ERR;
  }
  else
    *password = response->resp;

  free(response);
  return status;
}

static void cleanup(pam_handle_t *pamh, void *data, int pam_end_status) {
  if (data)
    free(data);
}

static int read_cache(int cache_fd, pam_handle_t *pamh, char *pass_md5, char *user, char *password, unsigned int credlife, int debug)
{
  unsigned long pag;
  unsigned long *pag_p;
  struct stat statbuf;
  char cache_md5[16];
  char import_buf[MAXPATHLEN+5];
  sec_login_handle_t login_context;
  error_status_t status;
  signed32 expiration;
  time_t now;

  if (fstat(cache_fd, &statbuf) != 0) {
    syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.read_cache - failed to stat cache file: %m");
    return PAM_AUTH_ERR;
  }

  if (statbuf.st_size != 16 + sizeof(pag)) {
    if (debug)
      syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.read_cache - cache file incorrect size: %d", statbuf.st_size);
    return PAM_AUTH_ERR;
  }

  if (read(cache_fd, cache_md5, 16) != 16) {
    syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.read_cache - cache file read failed: %m");
    return PAM_SYSTEM_ERR;
  }

  if (read(cache_fd, &pag, sizeof(pag)) != sizeof(pag)) {
    syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.read_cache - cache file read failed: %m");
    return PAM_SYSTEM_ERR;
  }

  if (debug)
    syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.read_cache - pag is %08x", pag);

  if (memcmp(pass_md5, cache_md5, 16) != 0) {
    syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.read_cache - password doesn't match cached password for user %s", user);
    return PAM_AUTH_ERR;
  }

  snprintf(import_buf, MAXPATHLEN+5, "FILE:%s/dcecred_%08x", CREDS_DIR, pag);
  import_buf[MAXPATHLEN+5-1] = '\0';

  sec_login_import_context(MAXPATHLEN+5, import_buf, &login_context, &status);
  if (status) {
    syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.read_cache - sec_login_import_context failed: %d", status);
    return PAM_AUTH_ERR;
  }

  sec_login_get_expiration(login_context, &expiration, &status);
  if (status && (status != sec_login_s_not_certified)) {
    syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.read_cache - sec_login_get_expiration failed: %d", status);
    return PAM_AUTH_ERR;
  }

  now = time(NULL);

  if (debug)
    syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.read_cache - context expiration = %d, now = %d, credlife = %d", expiration, now, credlife*60);

  if (now + credlife*60 > expiration) {
    sec_passwd_rec_t pw_entry;
    boolean32 reset_passwd;
    sec_login_auth_src_t auth_src;
    sec_passwd_str_t tmp_pw;

    if (debug)
      syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.read_cache - refreshing context");

    sec_login_refresh_identity(login_context, &status);
    if (status) {
      syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.read_cache - sec_login_refresh_identity failed for user %s: %d", user, status);
      return PAM_AUTH_ERR;
    }

    pw_entry.version_number = sec_passwd_c_version_none;
    pw_entry.pepper = NULL;
    pw_entry.key.key_type = sec_passwd_plain;
    strncpy( (char *)tmp_pw, password, sec_passwd_str_max_len);
    tmp_pw[sec_passwd_str_max_len] = '\0';
    pw_entry.key.tagged_union.plain = &(tmp_pw[0]);

    sec_login_validate_identity(login_context, &pw_entry, &reset_passwd, &auth_src, &status);
    if (status) {
      syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.read_cache - sec_login_validate_identity failed for user %s: %d", user, status);
      return PAM_AUTH_ERR;
    }
  }

  sec_login_release_context(&login_context, &status);

  if ((pag_p = malloc(sizeof(pag))) == NULL) {
    syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.read_cache - failed to allocate storage for pag");
    return PAM_BUF_ERR;
  }

  *pag_p = pag;

  if ((status = pam_set_data(pamh, "PAM_DCE_CACHE_PAG", pag_p, cleanup)) != PAM_SUCCESS) {
    syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.read_cache - pam_set_data failed: %d", status);
    return status;
  }

  return PAM_SUCCESS;
}

static int write_cache(int cache_fd, pam_handle_t *pamh, char *pass_md5) {
  char *krb5ccname = pam_getenv(pamh, "KRB5CCNAME");
  char *pag_str;
  unsigned long pag;

  if (!krb5ccname) {
    syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.write_cache - no KRB5CCNAME in pam environment");
    return PAM_AUTH_ERR;
  }

  if (!(pag_str = strrchr(krb5ccname, '_'))) {
    syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.write_cache - no apparent pag in KRB5CCNAME: %s", krb5ccname);
    return PAM_AUTH_ERR;
  }

  pag = strtol(pag_str+1, NULL, 16);

  if (ftruncate(cache_fd, 0) == -1) {
    syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.write_cache - ftruncate failed: %m");
    return PAM_SYSTEM_ERR;
  }

  if (write(cache_fd, pass_md5, 16) != 16) {
    syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.write_cache - cache file write failed: %m");
    return PAM_SYSTEM_ERR;
  }

  if (write(cache_fd, &pag, sizeof(pag)) != sizeof(pag)) {
    syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.write_cache - cache file write failed: %m");
    return PAM_SYSTEM_ERR;
  }

  return PAM_SUCCESS;
}


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


int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  int debug = 0;
  int index;

  for (index = 0; index < argc; index++) {
    if (strcmp(argv[index], "debug") == 0)
      debug = 1;
    else
      syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_acct_mgmt - unknown option %s", argv[index]);
  }

  if (debug)
    syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_acct_mgmt called");

  return PAM_SUCCESS;
}

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  char *user;
  int update = 0;
  int ignore_root = 0;
  int debug = 0;
  int use_first_pass = 0;
  unsigned int credlife = 240;
  char *password;
  int index;
  int status;
  int cache_fd;
  unsigned int numeric_hash;
  char cache_file[MAXPATHLEN];
  char pass_md5[16];
  char user_md5[16];
  char *pass_md5_p;
  AP_MD5_CTX md5_context;

  for (index = 0; index < argc; index++) {
    if (strcmp(argv[index], "debug") == 0)
      debug = 1;
    else if (strcmp(argv[index], "ignore_root") == 0)
      ignore_root = 1;
    else if (strcmp(argv[index], "update") == 0)
      update = 1;
    else if (strcmp(argv[index], "use_first_pass") == 0)
      use_first_pass = 1;
    else if (sscanf(argv[index], "credlife=%d", &credlife) == 1)
      ;
    else
      syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_authenticate - unknown option %s", argv[index]);
  }

  if (debug)
    syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_authenticate called - ignore_root=%d, update=%d, use_first_pass=%d, credlife=%d",
	   ignore_root, update, use_first_pass, credlife);

  if (update) {
    if (debug)
      syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_authenticate - update mode returning PAM_IGNORE");

    /* due to bug in pam implementation, must set flag so setcred phase (sometimes
     * called when it shouldn't be) knows whether to do its thing
     */
    pam_set_data(pamh, "PAM_DCE_CACHE_UPDATE_FLAG", 0, cleanup);

    return PAM_IGNORE;
  }

  if ((status = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS) {
    syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_authenticate - pam_get_user failed: %d", status);
    return status;
  }

  if (strchr(user, '/') || strchr(user, '.')) {
    syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_authenticate - unwanted characters in username: %s", user);
    return PAM_AUTH_ERR;
  }

  if (debug)
    syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_authenticate - user = %s", user);

  if (ignore_root && !strcmp(user, "root")) {
    if (debug)
      syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_authenticate - ignoring user root");
    return PAM_IGNORE;
  }

  if (use_first_pass)
    status = pam_get_item(pamh, PAM_AUTHTOK, (void **)&password);
  else
    status = acquire_password(pamh, &password);

  if (status != PAM_SUCCESS) {
    syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_authenticate - failed to get password %d", status);
    return status;
  }

  if ((status = pam_set_item(pamh, PAM_AUTHTOK, password)) != PAM_SUCCESS) {
    syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_authenticate - pam_set_item failed: %s", status);
    return status;
  }

  ap_MD5Init(&md5_context);
  ap_MD5Update(&md5_context, (const unsigned char *)user, strlen(user));
  ap_MD5Final(user_md5, &md5_context);
  memcpy(&numeric_hash, user_md5, sizeof(numeric_hash));
  numeric_hash %= 100;

  ap_MD5Init(&md5_context);
  ap_MD5Update(&md5_context, (const unsigned char *)password, strlen(password));
  ap_MD5Final(pass_md5, &md5_context);

  if ((pass_md5_p = malloc(16)) == NULL) {
    syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.read_cache - failed to allocate storage for password hash");
    return PAM_BUF_ERR;
  }

  memcpy(pass_md5_p, pass_md5, 16);
  if ((status = pam_set_data(pamh, "PAM_DCE_CACHE_PASS_MD5", pass_md5_p, cleanup)) != PAM_SUCCESS) {
    syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.read_cache - pam_set_data failed: %d", status);
    return status;
  }

  snprintf(cache_file, MAXPATHLEN, "%s/%02d/%s", CACHE_DIR, numeric_hash, user);
  cache_file[MAXPATHLEN - 1] = '\0';

  if (debug)
    syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_authenticate - cache file: %s", cache_file);

  if ((cache_fd = open(cache_file, O_RDWR)) == -1) {
    if (errno != ENOENT || debug)
      syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_authenticate - cache file open failed: %m");
    return PAM_AUTH_ERR;
  }

  index = 0;
  while ((index++ < 5) && ((status = lockf(cache_fd, F_TLOCK, 0)) == -1) && (errno == EAGAIN))
    sleep(1);

  if (status == -1) {
    close(cache_fd);
    syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_authenticate - failed to lock cache file: %m");
    return PAM_AUTH_ERR;
  }

  status = read_cache(cache_fd, pamh, pass_md5, user, password, credlife, debug);

  close(cache_fd);
  if (!use_first_pass)
    free(password);

  return status;
}

int pam_sm_close_session(pam_handle_t *pamh, int flags,	int argc, const char **argv)
{
  int debug = 0;
  int index;

  for (index = 0; index < argc; index++) {
    if (strcmp(argv[index], "debug") == 0)
      debug = 1;
    else
      syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_close_session - unknown option %s", argv[index]);
  }

  if (debug)
    syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_close_session called");

  return PAM_SUCCESS;
}

int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  int debug = 0;
  int index;

  for (index = 0; index < argc; index++) {
    if (strcmp(argv[index], "debug") == 0)
      debug = 1;
    else
      syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_open_session - unknown option %s", argv[index]);
  }

  if (debug)
    syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_open_session called");

  return PAM_SUCCESS;
}

int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  int debug = 0;
  int index;

  for (index = 0; index < argc; index++) {
    if (strcmp(argv[index], "debug") == 0)
      debug = 1;
    else
      syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_chauthtok - unknown option %s", argv[index]);
  }

  if (debug)
    syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_chauthtok called");

  return PAM_SUCCESS;
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  int debug = 0;
  int ignore_root = 0;
  int update = 0;
  int index;
  int status;
  char *user;

  for (index = 0; index < argc; index++) {
    if (strcmp(argv[index], "debug") == 0)
      debug = 1;
    else if (strcmp(argv[index], "ignore_root") == 0)
      ignore_root = 1;
    else if (strcmp(argv[index], "update") == 0)
      update = 1;
    else if (strncmp(argv[index], "credlife", 8) == 0)
      ;
    else if (strcmp(argv[index], "use_first_pass") == 0)
      ;
    else
      syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_setcred: unknown option %s", argv[index]);
  }

  if (debug)
    syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_setcred called - ignore_root=%d, update=%d", ignore_root, update);

  if (flags != PAM_ESTABLISH_CRED) {
    if (debug)
      syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_setcred - flags != PAM_ESTABLISH_CRED, returning PAM_IGNORE");

    return PAM_IGNORE;
  }

  if ((status = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS) {
    syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_setcred - pam_get_user failed: %d", status);
    return status;
  }

  if (strchr(user, '/') || strchr(user, '.')) {
    syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_setcred - unwanted characters in username: %s", user);
    return PAM_AUTH_ERR;
  }

  if (debug)
    syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_setcred - user = %s", user);

  if (ignore_root && !strcmp(user, "root")) {
    if (debug)
      syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_setcred - ignoring user root");
    return PAM_IGNORE;
  }

  if (!update) {
    unsigned long *pag_p;
    char krb5_env_buf[MAXPATHLEN+11+5];

    if ((status = pam_get_data(pamh, "PAM_DCE_CACHE_PAG", (const void **)&pag_p)) != PAM_SUCCESS) {
      if (status != PAM_NO_MODULE_DATA || debug)
	syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_setcred - pam_get_data failed for PAM_DCE_CACHE_PAG: %d", status);
      return status;
    }

    snprintf(krb5_env_buf, MAXPATHLEN+11+5, "KRB5CCNAME=FILE:%s/dcecred_%08x", CREDS_DIR, *pag_p);
    krb5_env_buf[MAXPATHLEN+11+5-1] = '\0';

    if (debug)
      syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_setcred - setting %s", krb5_env_buf);

    if ((status = pam_putenv(pamh, krb5_env_buf)) != PAM_SUCCESS) {
      syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_setcred - pam_putenv failed: %d", status);
      return status;
    }

    installpag(*pag_p);
  }
  else {
    int cache_fd;
    unsigned int numeric_hash;
    char cache_file[MAXPATHLEN];
    char *pass_md5_p;
    char user_md5[16];
    AP_MD5_CTX md5_context;

    if (pam_get_data(pamh, "PAM_DCE_CACHE_UPDATE_FLAG", (const void **)&pass_md5_p) == PAM_NO_MODULE_DATA) {
      if (debug)
	syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_setcred - update flag not set, return PAM_IGNORE");

      return PAM_IGNORE;
    }

    if ((status = pam_get_data(pamh, "PAM_DCE_CACHE_PASS_MD5", (const void **)&pass_md5_p)) != PAM_SUCCESS) {
      syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_setcred - pam_get_data failed: %d", status);
      return status;
    }

    ap_MD5Init(&md5_context);
    ap_MD5Update(&md5_context, (const unsigned char *)user, strlen(user));
    ap_MD5Final(user_md5, &md5_context);
    memcpy(&numeric_hash, user_md5, sizeof(numeric_hash));
    numeric_hash %= 100;

    if (strchr(user, '/') || strchr(user, '.')) {
      syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_setcred - unwanted characters in username: %s", user);
      return PAM_AUTH_ERR;
    }

    snprintf(cache_file, MAXPATHLEN, "%s/%02d/%s", CACHE_DIR, numeric_hash, user);
    cache_file[MAXPATHLEN - 1] = '\0';

    if (debug)
      syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_setcred - cache file: %s", cache_file);

    if ((cache_fd = open(cache_file, O_RDWR|O_CREAT, 0600)) == -1) {
      syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_setcred - cache file open failed: %m");
      return PAM_AUTH_ERR;
    }

    index = 0;
    while ((index++ < 5) && ((status = lockf(cache_fd, F_TLOCK, 0)) == -1) && (errno == EAGAIN))
      sleep(1);

    if (status == -1) {
      close(cache_fd);
      syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_setcred - failed to lock cache file: %m");
      return PAM_AUTH_ERR;
    }

    status = write_cache(cache_fd, pamh, pass_md5_p);
    close(cache_fd);
  }

  return status;
}
