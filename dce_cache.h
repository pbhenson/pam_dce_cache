#ifndef DCE_CACHE_H
#define DCE_CACHE_H

#define CACHE_DIR "/opt/dcelocal/var/security/cache"
#define CREDS_DIR "/opt/dcelocal/var/security/creds"

unsigned long dce_cache_authenticate(uid_t uid, char *user, char *password, int credlife, int forwardable, int certify, char *pass_md5, char *error_buf, int error_buf_size);

int dce_cache_update(uid_t uid, char *pass_md5, unsigned long pag, char *error_buf, int error_buf_size);

#endif
