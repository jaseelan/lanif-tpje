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



```









