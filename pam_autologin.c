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

#define PATH_AUTOLOGIN_CONF	"/tmp/autologin.conf"

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

int main (void)
{
    if (is_first_login ("tty1"))
	puts ("First login");
    else
	puts ("Not first login");

    struct stat st;
    if (0 > stat (PATH_AUTOLOGIN_CONF, &st)) {
	puts ("Autologin disabled");
	return EXIT_SUCCESS;
    }
    puts ("Autologin enabled");
    return EXIT_SUCCESS;
}
