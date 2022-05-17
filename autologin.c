// Copyright (c) 2022 by Mike Sharov <msharov@users.sourceforge.net>
// This file is free software, distributed under the ISC license.

#ifndef _GNU_SOURCE
    #define _GNU_SOURCE 1
#endif
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <utmp.h>
#include <paths.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>
#include <time.h>
#if __has_include(<sys/random.h>)
    #include <sys/random.h>
#endif
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#define UNUSED __attribute__((unused))

//{{{ wipe_buffer ------------------------------------------------------

// An explicitly noinline memset to ensure gcc doesn't think it knows better
static __attribute__((noinline)) void wipe_buffer (void* buf, size_t bufsz)
    { memset (buf, 0, bufsz); }

//}}}-------------------------------------------------------------------
//{{{ is_autologin_enabled

static bool is_autologin_enabled (void)
{
    struct stat st;
    return 0 == stat (PATH_AUTOLOGIN_CONF, &st);
}

//}}}-------------------------------------------------------------------
//{{{ is_first_login

static bool is_first_login (const char* tty)
{
    struct stat st = {};
    if (0 > stat (_PATH_WTMP, &st))
	return true;
    int fd = open (_PATH_WTMP, O_RDONLY);
    if (fd < 0)
	return true;
    //
    // wtmp can be huge; read in chunks from the end
    //
    off_t rend = st.st_size;
    while (rend > 0) {
	enum { UPerBlock = 16 };
	struct utmp utra [UPerBlock] = {};
	memset (&utra[0], 0, sizeof(utra));
	off_t rstart = rend - sizeof(utra);
	unsigned uistart = 0;
	if (rstart < 0) {
	    uistart = (-rstart + sizeof(utra[0]) - 1)/sizeof(utra[0]);
	    rstart = 0;
	}
	lseek (fd, rstart, SEEK_SET);
	unsigned btr = rend - rstart;
	if (btr != read (fd, &utra[uistart], btr))
	    break;
	for (unsigned i = UPerBlock; i-- > uistart;) {
	    if (utra[i].ut_type == BOOT_TIME || (utra[i].ut_type == USER_PROCESS && 0 == strcmp (tty, utra[i].ut_line))) {
		close (fd);
		return utra[i].ut_type == BOOT_TIME;
	    }
	}
	rend = rstart;
    }
    close (fd);
    return true;
}

//}}}-------------------------------------------------------------------
//{{{ xor encryption
//
// The username and password need to be obfuscated in the file because
// if the file is deleted, plaintext password may end up in the unused
// disk data and being next to the username, could be searched for.

static void encrypt (uint32_t key, char* buf, size_t bufsz)
{
    for (uint32_t *db = (uint32_t*) buf, *dbe = (uint32_t*)(buf+bufsz); db < dbe; ++db)
	*db ^= (key = key * 1664525 + 1013904223);
}

//}}}-------------------------------------------------------------------
//{{{ Written format packing

#if !__has_include(<sys/random.h>)
static ssize_t getrandom (void* buf, size_t buflen, unsigned flags UNUSED)
{
    int r = -1, fd = open (_PATH_DEV "random", O_RDONLY);
    if (fd >= 0) {
	r = read (fd, buf, buflen);
	close (fd);
    }
    return r == (int) buflen ? r : -1;
}
#endif

static size_t write_buffer (const char* username, const char* password, char* buf, size_t bufsz)
{
    memset (buf, 0, bufsz);
    size_t username_len = strlen (username),
	    password_len = strlen (password),
	    uplen = username_len+1+password_len+1;
    if (8+uplen > bufsz)
	return 0;
    //
    // 4 byte random key + pad-to-4 + username + ul + password + pl
    //
    unsigned pad = uplen%4 ? 4-uplen%4 : 0;
    if (4+pad != getrandom (buf, 4+pad, 0))
	return 0;
    uint32_t key = *(const uint32_t*)buf;
    buf += 4;
    char* p = buf+pad;
    memcpy (p, username, username_len);
    p += username_len;
    *p++ = username_len;
    memcpy (p, password, password_len);
    p += password_len;
    *p++ = password_len;

    encrypt (key, buf, p-buf);
    return 4+p-buf;
}

static void read_buffer (char* buf, size_t bufsz, const char** username, const char** password)
{
    *username = *password = NULL;
    uint32_t key = *(const uint32_t*)buf;
    encrypt (key, buf+4, bufsz-4);
    uint8_t password_len = buf[bufsz-1];
    if (password_len > bufsz-6)
	return;
    uint8_t username_len = buf[bufsz-1-password_len-1];
    uint32_t uplen = password_len+1 + username_len+1;
    uplen += uplen%4 ? 4-uplen%4 : 0;
    if (uplen+4 != bufsz)
	return;
    buf[bufsz-1] = buf[bufsz-1-password_len-1] = 0;
    *password = buf+bufsz-1-password_len;
    *username = buf+bufsz-1-password_len-1-username_len;
}

//}}}-------------------------------------------------------------------
//{{{ autologin file read/write

enum { MaxALSize = 64 };

static bool write_autologin (const char* username, const char* password)
{
    // Ensure root:root 0600
    if (0 != chown (PATH_AUTOLOGIN_CONF, 0, 0))
	return false;
    if (0 != chmod (PATH_AUTOLOGIN_CONF, S_IRUSR| S_IWUSR))
	return false;

    _Alignas(uint32_t) char albuf [MaxALSize];
    ssize_t usz = write_buffer (username, password, albuf, sizeof(albuf));
    if (!usz)
	return false;

    ssize_t bw = 0;
    int fd = open (PATH_AUTOLOGIN_CONF, O_WRONLY| O_CREAT| O_TRUNC, S_IRUSR| S_IWUSR);
    if (fd >= 0) {
	bw = write (fd, albuf, usz);
	close (fd);
    }
    wipe_buffer (albuf, sizeof(albuf));
    return bw == usz;
}

static size_t read_autologin (char* upbuf, size_t upbufsz, const char** username, const char** password)
{
    struct stat st;
    if (0 > stat (PATH_AUTOLOGIN_CONF, &st) || !st.st_size || (size_t) st.st_size > upbufsz)
	return 0;
    int fd = open (PATH_AUTOLOGIN_CONF, O_RDONLY);
    if (fd < 0)
	return 0;
    ssize_t br = read (fd, upbuf, st.st_size);
    close (fd);
    if (br != st.st_size)
	return 0;
    read_buffer (upbuf, br, username, password);
    if (!*username || !*password)
	return 0;
    return br;
}

//}}}-------------------------------------------------------------------
//{{{ autologin_with

static int autologin_with (pam_handle_t* pamh, const char* al_username, const char* al_password)
{
    //
    // Set username, if not set already
    //
    const char *cur_username = NULL;
    if (PAM_SUCCESS != pam_get_item (pamh, PAM_USER, (const void**) &cur_username))
	cur_username = NULL;
    if (!cur_username) {
	int r = pam_set_item (pamh, PAM_USER, al_username);
	if (r != PAM_SUCCESS) {
	    pam_syslog (pamh, LOG_ERR, "pam_set_item: %s", pam_strerror (pamh, r));
	    return PAM_USER_UNKNOWN;
	}
	pam_syslog (pamh, LOG_INFO, "automatically logging in user %s", al_username);
    } else if (0 != strcmp (cur_username, al_username)) {
	pam_syslog (pamh, LOG_INFO, "can not autologin user %s", cur_username);
	return PAM_SUCCESS; // already logging in somebody else
    }
    //
    // Set password
    //
    int r = pam_set_item (pamh, PAM_AUTHTOK, al_password);
    if (r != PAM_SUCCESS) {
	pam_syslog (pamh, LOG_ERR, "pam_set_item: %s", pam_strerror (pamh, r));
	return PAM_AUTH_ERR;
    }
    return PAM_SUCCESS;
}

//}}}-------------------------------------------------------------------
//{{{ setup_autologin

static int setup_autologin (pam_handle_t* pamh)
{
    //
    // Ask for username, just like pam_unix does
    //
    const char* username = NULL;
    int r = pam_get_user (pamh, &username, NULL);
    if (r == PAM_CONV_AGAIN)
	return PAM_INCOMPLETE;
    else if (r != PAM_SUCCESS || !username) {
	pam_syslog (pamh, LOG_ERR, "pam_get_user: %s", pam_strerror (pamh, r));
	return PAM_USER_UNKNOWN;
    } else if (username[0] == '-' || username[0] == '+') {
	// This check is copied from pam_unix
	pam_syslog (pamh, LOG_NOTICE, "bad username [%s]", username);
	return PAM_USER_UNKNOWN;
    }
    //
    // Disallow root autologin because the autologin file is owned by root
    //
    if (0 == strcmp (username, "root")) {
	pam_syslog (pamh, LOG_INFO, "not saving root for autologin");
	return PAM_SUCCESS; // continue login process normally
    }
    //
    // Ask for password
    //
    const char* password = NULL;
    r = pam_get_authtok (pamh, PAM_AUTHTOK, &password , NULL);
    if (r == PAM_CONV_AGAIN)
	return PAM_INCOMPLETE;
    else if (r != PAM_SUCCESS || !password) {
	pam_syslog (pamh, LOG_CRIT, "auth could not identify password for [%s]: %s", username, pam_strerror (pamh, r));
	return PAM_AUTH_ERR;
    }
    //
    // Write both to the conf file
    //
    if (!write_autologin (username, password))
	pam_syslog (pamh, LOG_ERR, "failed to save autologin: %s", strerror (errno));
	// Failure to save autologin should not fail the login
    pam_syslog (pamh, LOG_NOTICE, "successfully saved autologin credentials");
    return PAM_SUCCESS;
}

//}}}-------------------------------------------------------------------

int pam_sm_authenticate (pam_handle_t* pamh, int flags UNUSED, int argc, const char** argv)
{
    static bool s_tried_already = false;
    if (s_tried_already) {
	pam_syslog (pamh, LOG_INFO, "not retrying autologin after failure");
	return PAM_SUCCESS; // retrying login, possibly because the autologin saved password is wrong
    }
    s_tried_already = true;

    const char* cur_password = NULL;
    if (PAM_SUCCESS != pam_get_item (pamh, PAM_AUTHTOK, (const void**) &cur_password) || cur_password) {
	pam_syslog (pamh, LOG_INFO, "already authenticated");
	return PAM_SUCCESS; // already authenticated
    }

    if (!is_autologin_enabled()) {
	pam_syslog (pamh, LOG_INFO, "autologin is disabled");
	return PAM_SUCCESS;
    }

    int result = PAM_SUCCESS;
    _Alignas(uint32_t) char albuf [MaxALSize];
    const char *al_username = NULL, *al_password = NULL;
    size_t albufsz = read_autologin (albuf, sizeof(albuf), &al_username, &al_password);
    if (albufsz && al_username && al_password) {
	//
	// Autologin credentials are available
	//
	const char* login_tty = NULL;
	if (PAM_SUCCESS == pam_get_item (pamh, PAM_TTY, (const void**) &login_tty) && login_tty) {
	    const char* devname = strrchr (login_tty, '/');
	    if (devname)
		login_tty = devname + 1;
	}
	//
	// Only autologin once per tty. If the user has logged out,
	// he likely wants to login as somebody else. If "always" option
	// is given, then autologin anyway.
	//
	if (!login_tty || (argc > 0 && 0 == strcmp ("always", argv[0])) || is_first_login (login_tty))
	    result = autologin_with (pamh, al_username, al_password);
	else
	    pam_syslog (pamh, LOG_INFO, "not first login on %s, aborting autologin", login_tty);
    } else {
	//
	// Credentials not available; remember the next non-root login
	//
	pam_info (pamh, "Autologin will remember the next non-root login");
	result = setup_autologin (pamh);
    }
    wipe_buffer (albuf, sizeof(albuf));
    return result;
}

int pam_sm_chauthtok (pam_handle_t* pamh UNUSED, int flags UNUSED, int argc UNUSED, const char** argv UNUSED)
{
    if (!(flags & PAM_UPDATE_AUTHTOK) || (flags & PAM_PRELIM_CHECK))
	return PAM_IGNORE;
    //
    // Changing the password can be complicated and the actual code to do it
    // ought to stay in pam_unix. While it is possible to change the autologin
    // password here, it is probably safer to just reset and save the next login.
    //
    struct stat st;
    if (0 > stat (PATH_AUTOLOGIN_CONF, &st) || !st.st_size)
	return PAM_SUCCESS;
    //
    // To reset, wipe the old data and truncate the file to zero
    //
    int fd = open (PATH_AUTOLOGIN_CONF, O_WRONLY);
    if (fd >= 0) {
	_Alignas(uint32_t) char albuf [MaxALSize];
	memset (albuf, 0, sizeof(albuf));
	write (fd, albuf, st.st_size < (off_t) sizeof(albuf) ? (size_t) st.st_size : sizeof(albuf));
	lseek (fd, 0, SEEK_SET);
	ftruncate (fd, 0);
	close (fd);
    }
    pam_info (pamh, "Autologin forgot saved credentials");
    return PAM_SUCCESS;
}

int pam_sm_setcred (pam_handle_t* pamh UNUSED, int flags UNUSED, int argc UNUSED, const char** argv UNUSED)
    { return PAM_SUCCESS; }
int pam_sm_acct_mgmt (pam_handle_t* pamh UNUSED, int flags UNUSED, int argc UNUSED, const char** argv UNUSED)
    { return PAM_IGNORE; }
int pam_sm_open_session (pam_handle_t* pamh UNUSED, int flags UNUSED, int argc UNUSED, const char** argv UNUSED)
    { return PAM_IGNORE; }
int pam_sm_close_session (pam_handle_t* pamh UNUSED, int flags UNUSED, int argc UNUSED, const char** argv UNUSED)
    { return PAM_IGNORE; }
