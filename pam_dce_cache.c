
/*
 * pam_dce_cache.c
 *
 * Copyright 2001 Paul B. Henson <henson@acm.org>
 *
 * See COPYRIGHT file for details
 *
 */

#include <errno.h>
#include <stdlib.h>
#include <strings.h>
#include <syslog.h>
#include <sys/param.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <dce/sec_login.h>
#include "dce_cache.h"

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

static void null_cleanup(pam_handle_t *pamh, void *data, int pam_end_status) {
}

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
  int ignore_root = 0;
  int ignore_root_auth = 0;
  int forwardable = 0;
  int debug = 0;
  int certify = 0;
  int use_first_pass = 0;
  unsigned int credlife = 240;
  char *password;
  int index;
  int status;
  struct passwd pwd;
  char pwd_buf[1024];
  char error_buf[1024];
  char *pass_md5;
  sec_login_handle_t dce_context;
  unsigned long *pag_p;
  sec_login_auth_src_t auth_src;
  sec_login_tkt_info_t tkt_info;
  sec_passwd_rec_t pw_entry;
  boolean32 reset_passwd;
  sec_passwd_str_t dce_pw;
  error_status_t dce_st;
  
  for (index = 0; index < argc; index++) {
    if (strcmp(argv[index], "debug") == 0)
      debug = 1;
    else if (strcmp(argv[index], "ignore_root") == 0)
      ignore_root = 1;
    else if (strcmp(argv[index], "ignore_root_auth") == 0)
      ignore_root_auth = 1;
    else if (strcmp(argv[index], "forwardable") == 0)
      forwardable = 1;
    else if (strcmp(argv[index], "certify") == 0)
      certify = 1;
    else if (strcmp(argv[index], "use_first_pass") == 0)
      use_first_pass = 1;
    else if (sscanf(argv[index], "credlife=%d", &credlife) == 1)
      ;
    else
      syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_authenticate - unknown option %s", argv[index]);
  }

  if (debug)
    syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_authenticate called - ignore_root=%d, use_first_pass=%d, credlife=%d",
	   ignore_root, use_first_pass, credlife);

  if ((status = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS) {
    syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_authenticate - pam_get_user failed: %d", status);
    return status;
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

  if ((ignore_root || ignore_root_auth) && !strcmp(user, "root")) {
    if (debug)
      syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_authenticate - ignoring user root");
    return PAM_IGNORE;
  }

  if (!getpwnam_r(user, &pwd, pwd_buf, 1024)) {
    if (debug)
      syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_authenticate - getpwnam_r failed");
    return PAM_USER_UNKNOWN;
  }

  if (!(pag_p = (unsigned long *)malloc(sizeof(unsigned long)))) {
    syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_authenticate - malloc failed");
    return PAM_BUF_ERR;
  }

  if (!(pass_md5 = malloc(16))) {
    syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_authenticate - malloc failed");
    return PAM_BUF_ERR;
  }

  if ((*pag_p = dce_cache_authenticate(pwd.pw_uid, user, password, credlife, forwardable, certify, pass_md5, error_buf, 1024)) != 0) {
    if ((status = pam_set_data(pamh, "PAM_DCE_CACHE_PAG", pag_p, cleanup)) != PAM_SUCCESS) {
      syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_authenticate - pam_set_data failed: %d", status);
      return status;
    }
    return PAM_SUCCESS;
  }
  
  if (*error_buf)
    syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_authenticate - dce_cache_authenticate failed for %s - %s", user, error_buf);

  sec_login_setup_identity(user, sec_login_no_flags, &dce_context, &dce_st);
  
  if (dce_st) {
    syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_authenticate - sec_login_setup_identity failed - %d", dce_st);
    return PAM_AUTH_ERR;
  }

  pw_entry.version_number = sec_passwd_c_version_none;
  pw_entry.pepper = NULL;
  pw_entry.key.key_type = sec_passwd_plain;

  strncpy((char *)dce_pw, password, sec_passwd_str_max_len);
  dce_pw[sec_passwd_str_max_len] = '\0';
  pw_entry.key.tagged_union.plain = &(dce_pw[0]);

  if (forwardable) {
    tkt_info.options = sec_login_tkt_forwardable;
    sec_login_tkt_request_options(dce_context, &tkt_info, &dce_st);
  }

  if (
#ifndef ROOT_ONLY
      getuid() == 0 &&
#endif
      certify)
    sec_login_valid_and_cert_ident(dce_context, &pw_entry, &reset_passwd, &auth_src, &dce_st);
  else
    sec_login_validate_identity(dce_context, &pw_entry, &reset_passwd, &auth_src, &dce_st);

  if (dce_st) {
    syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_authenticate - sec_login_valid_and_cert_ident failed for %s - %d", user, dce_st);
    sec_login_purge_context(&dce_context, &dce_st);
    return PAM_AUTH_ERR;
  }

  if ((status = pam_set_data(pamh, "PAM_DCE_PASS_MD5", pass_md5, cleanup)) != PAM_SUCCESS) {
    syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_authenticate - pam_set_data failed: %d", status);
    return status;
  }

  if ((status = pam_set_data(pamh, "PAM_DCE_CONTEXT", dce_context, null_cleanup)) != PAM_SUCCESS) {
    syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_authenticate - pam_set_data failed: %d", status);
    return status;
  }
  
  return PAM_SUCCESS;
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
  int index;
  int status;
  sec_login_handle_t dce_context;
  char *user;
  char krb5_env_buf[MAXPATHLEN+11+5];
  unsigned long *pag_p;

  for (index = 0; index < argc; index++) {
    if (strcmp(argv[index], "debug") == 0)
      debug = 1;
    else if (strcmp(argv[index], "ignore_root") == 0)
      ignore_root = 1;
    else if (strcmp(argv[index], "ignore_root_auth") == 0)
      ignore_root = 1;
    else if (strcmp(argv[index], "forwardable") == 0)
      ;
    else if (strcmp(argv[index], "certify") == 0)
      ;
    else if (strncmp(argv[index], "credlife", 8) == 0)
      ;
    else if (strcmp(argv[index], "use_first_pass") == 0)
      ;
    else
      syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_setcred: unknown option %s", argv[index]);
  }
  
  if (debug)
    syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_setcred called - ignore_root=%d", ignore_root);
  
  if (flags != PAM_ESTABLISH_CRED) {
    if (debug)
      syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_setcred - flags != PAM_ESTABLISH_CRED, returning PAM_IGNORE");
    
    return PAM_IGNORE;
  }

  if ((status = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS) {
    syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_setcred - pam_get_user failed: %d", status);
    return status;
  }
  
  if (ignore_root && !strcmp(user, "root")) {
    if (debug)
      syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_setcred - ignoring user root");
    return PAM_IGNORE;
  }

  if ((status = pam_get_data(pamh, "PAM_DCE_CACHE_PAG", (const void **)&pag_p)) == PAM_SUCCESS) {

    if (debug)
      syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_setcred - using pag %d", *pag_p);
    
    snprintf(krb5_env_buf, MAXPATHLEN+11+5, "KRB5CCNAME=FILE:%s/dcecred_%08x", CREDS_DIR, *pag_p);
    krb5_env_buf[MAXPATHLEN+11+5-1] = '\0';
  
    if (debug)
      syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_setcred - setting %s", krb5_env_buf);
    
    if ((status = pam_putenv(pamh, krb5_env_buf)) != PAM_SUCCESS) {
      syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_setcred - pam_putenv failed: %d", status);
      return status;
    }
  
    installpag(*pag_p);

    return PAM_SUCCESS;
  }
  else if ((status = pam_get_data(pamh, "PAM_DCE_CONTEXT", (const void **)&dce_context)) == PAM_SUCCESS) {
    struct passwd pwd;
    char pwd_buf[1024];
    error_status_t dce_st;
    char *krb5ccname;
    char *pag_str;
    unsigned long pag;
    char *pass_md5;
    char error_buf[1024];
    
    if (debug)
      syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_setcred - using dce_context");
    
    if (!getpwnam_r(user, &pwd, pwd_buf, 1024)) {
      if (debug)
	syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_setcred - getpwnam_r failed");
      return PAM_USER_UNKNOWN;
    }

    sec_login_set_context(dce_context, &dce_st);

    if (dce_st) {
      syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_setcred - sec_login_set_context failed - %d", dce_st);
      sec_login_purge_context(&dce_context, &dce_st);      
      return PAM_AUTH_ERR;
    }

    if (!(krb5ccname = getenv("KRB5CCNAME"))) {
      syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_setcred - KRB5CCNAME not found");
      return PAM_AUTH_ERR;
    }

    snprintf(krb5_env_buf, MAXPATHLEN+11+5, "KRB5CCNAME=%s", krb5ccname);
    krb5_env_buf[MAXPATHLEN+11+5-1] = '\0';
	
    if ((status = pam_putenv(pamh, krb5_env_buf)) != PAM_SUCCESS) {
      syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_setcred - pam_putenv failed: %d", status);
      return status;
    }
    
    if (!(pag_str = strrchr(krb5ccname, '_'))) {
      syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_setcred - no apparent pag in KRB5CCNAME: %s", krb5ccname);
      return PAM_AUTH_ERR;
    }
    
    pag = strtol(pag_str+1, NULL, 16);

#ifdef IBM_DCE_ONLY
    {
      char path[MAXPATHLEN];

      snprintf(path, MAXPATHLEN, "%s/dcecred_%08x", CREDS_DIR, pag);
      path[MAXPATHLEN-1] = '\0';
      chown(path, pwd.pw_uid, pwd.pw_gid);
      
      snprintf(path, MAXPATHLEN, "%s/dcecred_%08x.data", CREDS_DIR, pag);
      path[MAXPATHLEN-1] = '\0';
      chown(path, pwd.pw_uid, pwd.pw_gid);

      snprintf(path, MAXPATHLEN, "%s/dcecred_%08x.data.db", CREDS_DIR, pag);
      path[MAXPATHLEN-1] = '\0';
      chown(path, pwd.pw_uid, pwd.pw_gid);

      snprintf(path, MAXPATHLEN, "%s/dcecred_%08x.nc", CREDS_DIR, pag);
      path[MAXPATHLEN-1] = '\0';
      chown(path, pwd.pw_uid, pwd.pw_gid);
    }
#endif

    status = pam_get_data(pamh, "PAM_DCE_PASS_MD5", (const void **)&pass_md5);
    if (status != PAM_SUCCESS) {
      syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_setcred - failed to get hashed password %d", status);
      return PAM_SUCCESS;
    }

    if (!dce_cache_update(pwd.pw_uid, pass_md5, pag, error_buf, 1024)) {
      if (*error_buf)
	syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_setcred - dce_cache_update failed - %s", error_buf);
    }
    
    return PAM_SUCCESS;
  }
  else {
    syslog(LOG_AUTH|LOG_ERR, "pam_dce_cache.pam_sm_setcred - neither pag nor context found");
    return PAM_AUTH_ERR;
  }
}
