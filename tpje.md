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
03)  Windows Recon: Zenmap (nmap gui)

```
nmap -T4 -A -v 10.0.17.0/20
```

04)  Scan the Server 2

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








