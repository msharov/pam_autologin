# PAM Autologin

## Project Moved

This project has moved to [SourceForge](https://sourceforge.net/p/pam-autologin/).
Please update your links. This repository will be removed soon.

## Description

This module logs in automatically with saved username and password.

Because this allows a normal login process, the saved password can be
used to unlock encrypted files at login, such as ssh keys, gpg keys,
gnome-keyring, or an encrypted home directory. Encrypting sensitive
information is necessary even on a desktop, where the risk of theft is
negligible, because for most people, the main threat comes from remote
attackers who may be able to steal these local files.

On laptops, which are frequently stolen, autologin could still be
enabled when safely at home, and disabled when travelling. When using
this module, autologin is easy to turn on and off because the a password
is available either way and can be used for encryption. Other ways of
doing autologin, such as the `-a` option to `getty`, use no password and
bypass authentication entirely, making it impossible to setup encrypted
content.

Using autologin is safe and secure on any computer that is not at risk of
being stolen. The saved credentials file is readable only by root and is
inaccessible to remote attacks or malware that run under user privileges.

## Installation

[PAM](https://www.linux-pam.org) is the only build dependency,
and you almost certainly have it already.

```sh
./configure --prefix=/usr
make install
```

Then add `pam_autologin` to the top of the auth section of the PAM
config file for the app you want to use. For the usual `login` from
`util-linux`, edit `/etc/pam.d/login` to something like this:

```pam
#%PAM-1.0
auth    include pam_autologin
auth    include system-local-login
account include system-local-login
session include system-local-login
```

To save a login, create empty `/etc/security/autologin.conf`.

```sh
touch /etc/security/autologin.conf
```

The next time you reboot, you will see a message telling you that the next
non-root login will be saved. Log in and it will be. Reboot again and you
should be logged in automatically.

By default, autologin only happen once on each tty. If you log out,
the assumption is that you want to log in with another account,
so you will be prompted for both username and password. To log in
automatically every time, you can give `pam_autologin` the `always`
option in `/etc/pam.d/login`:
```pam
auth include pam_autologin always
```

## UnPAMmed

... or not quite yet. The console login prompt actually comes from the
`getty` process. It prompts for the username and forwards it to the
`login` program, which prompts for the password and logs you in. `login`
is a PAM application and so loads this autologin module, but `getty`
does not, and so will prompt for the username anyway. `login` then gets
the username from `getty`, gets the password from this autologin module,
and logs you in. This behavior, of automatically logging in one user with
a saved password and presenting a normal login to others, may actually
be desirable in some situations.

For full autologin you'll need to add the `-n` flag to `getty` so it will
launch `login` immediately. If you are using traditional `sysvinit`,
this is easily done by editing `/etc/inittab`. If you are using systemd,
you'll need to add a service drop-in file:

```sh
systemctl edit getty@.service
```

This will create `/etc/systemd/system/getty@.service.d/override.conf`,
where you can put the following:

```ini
ExecStart=
ExecStart=-/sbin/agetty -n - $TERM
```

Note that you have to have an empty `ExecStart=` line first, to reset
this variable. The second line is pretty much what `ExecStart` was in
the file you are editing, but with the `-n` added.

Some PAM applications may also prevent full autologin if they prompt
before PAM tells them to. `lightdm`, for example, will always ask first,
before initiating a PAM conversation, and so can not fully benefit from
this module.

## Uninstallation

To stop autologin, delete the saved credentials file:

```sh
shred -u /etc/security/autologin.conf
```

Use the `shred` program from `util-linux`, zeroing out the file data
before unlinking it, to ensure your password will not end up floating
in the unallocated storage area, where a determined attacked could find
and read it. `autologin.conf` is already lightly encrypted, but that
merely makes it look like random data. To allow the computer to decode
it without any help from you, the decryption key must be stored in the
file, and thus can offer only obfuscation, not protection.

Without the config file, the autologin module does nothing. If you want
to turn it off temporarily, you can leave the PAM configuration the way
it is. When you are in a safe place again, create an empty conf file. The
next login will be saved, and your life will be easy once again.

## Bugs

Report bugs on the github [bug tracker](https://github.com/msharov/pam_autologin/issues)
