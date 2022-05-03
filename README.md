# PAM Autologin

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
bypass authentication entirely, making it impossible to unlock encrypted
content at login.

Using autologin is safe and secure on any computer that is not at risk of
being stolen. The saved credentials file is readable only by root and is
inaccessible to remote attacks or malware that run under user privileges.

## Installation

PAM is the only build dependency, and you almost certainly have it already.
```sh
./configure --prefix=/usr
make install
```
Then add `pam_autologin` to the top of the auth section of the PAM config
file for the app you want to use. For `login` from `util-linux`, edit
`/etc/pam.d/login` to something like this:
```pam
#%PAM-1.0
auth    include pam_autologin
auth    include system-local-login
account include system-local-login
session include system-local-login
```
To save a login, create empty `/etc/security/pam_autologin.conf`.
```sh
touch /etc/security/pam_autologin.conf
```
The next time you reboot, you will see a message telling you that the next
non-root login will be saved. Log in and it will be. Reboot again and you
should be logged in automatically.

## UnPAMmed

... or not quite yet. Unfortunately there is one more thing that needs
doing. By default, each virtual console is owned by a `getty` process,
which is the one that prompts you for the username. It does that because
in the ancient times consoles were real physical terminals, attached to
the central mainframe by various means, and getty had to figure out what
kind of a connection it had and the easiest way to do so was to get some
input from the user. Today there is no such thing as a serial terminal
any more, but tradition prevails, and getty is still the one tasked with
prompting for the username. Because getty is not a PAM app, it does not
use this autologin module. It will instead pass the username to `login`
on the command line. This means you still have to type in the username,
even though `login` will be able to use the saved password and not ask
you for one.

To fix this problem, you have to add the `-n` flag to `getty`, telling it
to launch `login` right away. Feel free to read about this option on the
`getty` man page, where you will find several entertaining warnings about
how the world will end if `getty` can't figure out your serial terminal,
as if anybody still had those things...

If you are using traditional `sysvinit`, this is easily done by editing
`/etc/inittab`. If you are using systemd, you'll need to add a service
override:
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

Whew.

Unfortunately, you may run into similar problems with other apps, which
prompt first and start PAM after. `lightdm`, for example, will always
ask first, before initiating a PAM conversation, and so can not fully
benefit from this module.

## Uninstallation

To stop autologin, delete the saved credentials file:
```sh
shred -u /etc/security/pam_autologin.conf
```
Use the `shred` program from `util-linux` to zero out the file data
before unlinking it. This ensures your password will not end up floating
aimlessly in the unallocated storage area, where it could be found and
read. `pam_autologin.conf` already does lightly encrypt it, but since
the computer has to be able to read the file without any help from you,
everything needed to decode the file must already be in it. So shred
before deleting to be sure.

Without the config file, the autologin module does nothing. If you want
to turn it off temporarily, you can leave the PAM configuration the way
it is. Then when you are in a safe place again, create an empty conf
file again, the next login will be saved, and your life is easy again.

## Bugs

Report bugs on the github [bug tracker](https://github.com/msharov/pam_autologin/issues)
