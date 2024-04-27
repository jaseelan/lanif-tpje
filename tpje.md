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
ip a
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

```
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

```







