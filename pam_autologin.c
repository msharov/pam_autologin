// Copyright (c) 2022 by Mike Sharov <msharov@users.sourceforge.net>
// This file is free software, distributed under the ISC license.

#include <pam_client.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <utmp.h>
#include <paths.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <sys/random.h>

//{{{ Constants --------------------------------------------------------

#define PATH_AUTOLOGIN_CONF	"/tmp/autologin.conf"
enum { MaxALSize = 64 };

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

static bool write_autologin (const char* username, const char* password)
{
    _Alignas(uint32_t) char albuf [MaxALSize];
    size_t usz = write_buffer (username, password, albuf, sizeof(albuf));
    if (!usz)
	return false;
    int fd = open (PATH_AUTOLOGIN_CONF, O_WRONLY| O_CREAT| O_TRUNC, S_IRUSR| S_IWUSR);
    if (fd < 0)
	return false;
    ssize_t bw = write (fd, albuf, usz);
    memset (albuf, 0, sizeof(albuf));
    close (fd);
    return bw == (ssize_t) usz;
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

int main (void)
{
    _Alignas(uint32_t) char albuf [MaxALSize];
    const char* username = NULL;
    const char* password = NULL;
    size_t albufsz = read_autologin (albuf, sizeof(albuf), &username, &password);
    if (!albufsz)
	puts ("Autologin disabled");
    else
	printf ("Autologin enabled for %s: %s\n", username, password);
    memset (albuf, 0, sizeof(albuf));
    if (!is_first_login ("tty1"))
	puts ("Not first login");
    else
	puts ("First login");
    if (write_autologin ("johndoe", "iloveyoum"))
	puts ("Wrote autologin");
    return EXIT_SUCCESS;
}
