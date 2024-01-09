---
title: DFIR cheat sheet
layout: page
tags: dfir forensics volatility ir ftk mft evtx
---

# DFIR Cheatsheet

Wrap-up of a bunch of open source information about incident response and digital forensics.

## 📖 Overall methodology - Digital Forensics for IR

1. [RAM Memory acquisition](https://digital-forensics.sans.org/media/rekall-memory-forensics-cheatsheet.pdf) (If the acquisition make sense)
   1. FTK Imager
   2. [Wimpmem](https://github.com/Velocidex/WinPmem/releases/tag/v4.0.rc1)
   3. [DumpIp](https://github.com/thimbleweed/All-In-USB/blob/master/utilities/DumpIt/DumpIt.exe)
2. Check if machine has full disk encryption, if so LIVE image it before turning it off.
   1. [EDD](http://www.magnetforensics.com/products/encrypted-disk-detector/)
3. Disk imaging

Due to [wearing leveling](https://en.wikipedia.org/wiki/Wear_leveling) when imaging SSD Drives always prefer to image the system LIVE. Nice intro paper on the subject can be found [here](https://siaiap34.univali.br/sbseg2015/anais/WFC/artigoWFC01.pdf) (PT/BR) and [here](https://www.youtube.com/watch?v=v_YKD0BRGLM&list=PLfouvuAjspTqyfrgYO76VOwvVqK1AsMwK&index=43).

   1. FTK Imager
   2. gkape
   3. Arsenal Image Mounter
   4. dc3dd / dd

## 🔥 Quick Wins

Evidence of execution / opened files, [check OS version for each indicator](https://1234n6-my.sharepoint.com/:x:/p/adam/EU3Fk3ec6NdPsSQx1eA1sfwB_R_fRa4tJ4c1FR6WJlWIEA?rtime=bKtN5Ka82Eg)

:::info
Most tools to analyze these artifacts used are from [eric zimmerman](https://twitter.com/ericrzimmerman) [github](https://ericzimmerman.github.io/#!index.md), thanks for the amazing tools and effort Eric!
:::

- [ShimCache](https://github.com/mandiant/ShimCacheParser) => `HKLM\SYSTEM\CurrentControlSet\Control\SessionManager\AppCompatCache\AppCompatCache
`
- AmCache (regripper) => `\%SystemRoot%\AppCompat\Programs\Amcache.hve`
- [Prefetch files](https://github.com/EricZimmerman/PECmd) => `C:\Windows\Prefetch\*.pf`
- [Jumplists](https://github.com/EricZimmerman/JLECmd) =>`%HOME%\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\*-ms`
- LNK files => `%HOME%\AppData\Roaming\Microsoft\Windows\Recent Items\*`
- Shellbags => `%HOME%\AppData\Local\Microsoft\Windows\UsrClass.dat` | `HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\Shell`
- Registry (regripper) => `C:\Windows\System32\config\{SAM,SOFTWARE,SYSTEM,SECURITY}`
  - NTUser.dat in user profile folder `C:\users\malicious_user\ntuser.dat`

## 🔍Triaging

- Look for high entropy executable in file system (possible malware) with [densityscout](https://cert.at/media/files/downloads/software/densityscout/files/densityscout_build_45_windows.zip)
  - `densityscout -s cpl,exe,dll,ocx,sys,scr -p 0.1 -o results.txt c:\Windows\System32`
- Grab memory image
- Grab hibernation file
- Grab page file
- Grab registry hives
- Grab event logs (evt/etvx)
- Grab the Master File Table ($MFT)

Memory acquisition on virtualised platforms

- VMWare = .vmem file
- MS Hyper-V = .bin file
- Parallels = .mem file
- VirtualBox = .sav file (partial)

## 🧱Mounting evidences

**Mounting E01**

```bash
ewfmount image.E01 /mnt/ewf_mount && mount -o ro,loop,show_sys_files,streams_interface=windows /mnt/ewf_mount/ewf1 /mnt/windows_mount
```

**Umount the image:**

```bash
umount /mnt/windows_mount && umount /mnt/ewf_moun
```

**Mounting vmkd as read-only**

```bash
$ mount /disk/disk.vmdk /path -o ro,loop
```

**Mounting raw/dd**

1. List disk information
2. Get start offset and multiply by sector size => 2048 * 512 = 1048576

```bash
$ sudo mount disk.raw /mnt/mountpoint -o ro,offset=1048576
```

**Mounting vmdk**

```bash
$ guestmount -a Joao\ Topete.vmdk -i --ro /mnt/leforense/joao-pc
```

**Converting vmdk to raw**

```bash
$ qemu-img convert -f vmdk Joao\ Topete.vmdk -O raw joao.raw
```

**Retrieving $MFT from raw image**

```bash
$ mmls image.raw
$ icat -o <offset, 2048> image-file.E01 0 > image.mft
# then generate timeline with analyzeMFT.py
$ analyzemft.py -f /path/to/mounted/windows/image/\$MFT -a -e -o analyzemft-results.csv
# Or generate with MFTEcmd
MFTECmd.exe -f "C\$MFT" --body "E:\timeline" --bodyf test.body --blf --bdl E:
mactime -z America/Sao_Paulo -y -d -b /test.body 2019-07-23..2019-08-07 > /test-filesystem-timeline.csv
```

**Mounting volume shadow copy**

- [ShadowExplorer](https://www.shadowexplorer.com/downloads.html)

Windows - mount the image image file using Arsenal Image Mounter

```bash
vssadmin list shadows /for=D:
# Then we just need to create a symbolic link and access it
mklink link created for C:\path\to\link <<===>> \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy{1|2|3|4}
```

```bash
# From raw image
vshadowmount /mnt/ewf_mount/ewf1 /mnt/vss & cd /mnt/vss && for i in vss* ; do mountwin $i /mnt/shadow_mount/$i ; done
# From mounted image
vshadowinfo /mnt/ewf_mount/ewf1
```

## 💾Registry Analysis

[https://github.com/keydet89/RegRipper2.8](https://github.com/keydet89/RegRipper2.8)

**Full analysis**

```bash
$ rip.pl </path/to/registry/hive/NTUUSER.DAT> -f ntuser > user.txt
$ rip.pl </path/to/registry/hive/SYSTEM> -f system > system.txt
$ rip.pl </path/to/registry/hive/SOFTWARE> -f software > software.txt
$ rip.pl </path/to/registry/hive/SECURITY> -f security > security.txt
```

**Recent docs opened from user**

[rip.pl](http://rip.pl/)
```bash
$ rip.pl -r c:\Users\<username>\NTUSER.DAT -p recentdocs > rip-recent-docs-resultst.txt
```

**Recent searches have been done from the Start menu**

```bash
$ rip.pl -r c:\Users\<username>\NTUSER.DAT -p wordwheelquery > rip-recent-start-searches-resultst.txt
```

**[Searching for specific strings](https://www.andreafortuna.org/2020/03/04/recmd-command-line-tool-for-windows-registry-analysis)**

```powershell
RECmd.exe -f .\NTUSER.dat --sk Skype
RECmd.exe -f .\UsrClass.dat --sd Skype
```

**Check for bad stuff in keys of auto start applications**

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Runonce`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunonceEx`

## 📖Memory analysis methodology

Identify rogue processes

- Analyze processes
  - Legitimate process?
  - Name spelled right?
  - Fits with system context?
- Full path
  - Is the process executable in the usual place?
  - Is it running from user or temp directories?
- Parent process
  - Is it as expected?
- Command line
  - Does it have the right switches?
- Start time
  - Was it started at boot or something else?
  - Did the process start close the time of a known incident?
- Security ID
  - Does the SID make sense? Would a system process run with a user accounts’ SID?
- Analyzing process objects
  - DLLs
  - Handles
    - Files and directories
      - Look at occurrence of use. Malware files should, historically, be the least accessed files on the system
    - Registry
    - Events
  - Threads
  - Sockets
- Network artifacts
  - Suspicious ports
    - out-of-the-ordinary ports
    - listening ports (backdoors)
  - Suspicious connections
    - Anything connecting out
    - Known bad-IPs
    - Creation time matching an incident
  - Suspicious processes
    - Should this process have networking capabilities?
- Detecting code injection
  - Look for DLL injection and process hollowing
- Rootkit detection
  - Not a big thing anymore, most AV does a good job at detecting this
  - Hides in
    - System service descriptor tables
    - Interrupt descriptor tables
    - Function import address tables
    - I/O request packets
- Acquiring processes and drivers
  - Submit for reverse engineering or AV analysis
  - Review strings
    - add to bad-words list
    - You can export Volatility switches so you don’t have to set them all the time:
      - export VOLATILITY_PROFILE=Win7SP1x64
      - export VOLATILITY_LOCATION=file://image.img
    - imagecopy can be used to convert crash dumps and hibernation files to raw memory
    - Started applications for your timeline
      - pslist
      - psscan
      - pstree
    - Run dllist to see what DLLs were loaded as part of interesting processes
    - Check handles and services
    - Run connections, connscan, sockets, sockscan and netscan to see network connections
    - malfind to find hidden and injected code
    - ldrmodules to find unlinked DLLs
    - psxview, driverscan, ssdt, ssdt_ex, apihooks, idt and driverirp to find rootkits

## 💽Volatility

**Identification of profile**

  ```bash
  volatility -f /path/to/memory/dump.001 imageinfo
  ```

  **Network connections**

  ```bash
  volatility -f /path/to/memory/dump.001 --profile=<profile> netscan > netscan-results.txt
  volatility -f /path/to/memory/dump.001 --profile=<profile> connections > connections-results.txt
  volatility -f /path/to/memory/dump.001 --profile=<profile> connscan > connscan-results.txt
  volatility -f /path/to/memory/dump.001 --profile=<profile> sockets > sockets-results.txt
  volatility -f /path/to/memory/dump.001 --profile=<profile> sockscan > sockscan-results.txt
  ```

  **Extract cached files from memory**

  ```bash
  volatility -f /path/to/memory/dump.001 --profile=<profile> filescan > filescan-results.txt
  # Look through the list of cached files for anything interesting, then run the following to extract it:
  volatility -f /path/to/memory/dump.001 --profile=<profile> dumpfiles -n -r <filename> --dump-dir=./
  ```

  **Rogue processes**

  ```bash
  # Processes running
  volatility -f /path/to/memory/dump.001 --profile=<profile> psscan
  volatility -f /path/to/memory/dump.001 --profile=<profile> pstree
  volatility -f /path/to/memory/dump.001 --profile=<profile> pstotal --cmd --output=dot --output-file=/path/pstotal-graph.dot && xdot pstotal.dot
  
  volatility -f /path/to/memory/dump.001 --profile=<profile> malprocfind > malprocfind-results.txt && grep False malprocfind-results.txt
  ```

  **Loaded DLLs of processes**

  ```bash
  volatility -f /path/to/memory/dump.001 --profile=<profile> dlllist -p <pidofprocess> > dlllist-results.txt
  ```

  **Processes handles**

  ```bash
  volatility -f /path/to/memory/dump.001 --profile=<profile> handles -p <pidofprocess> > handles-results.txt
  # Shows all the resources the process interacted with.
  volatility -f /path/to/memory/dump.001 --profile=<profile> handles -p <pidofprocess> -t Key > handles-key-results.txt
  # Shows all the registry keys the process interacted with.
  volatility -f /path/to/memory/dump.001 --profile=<profile> handles -p <pidofprocess> -t File > handles-file-results.txt
  ```

Who started each process?

  ```bash
  volatility -f /path/to/memory/dump.001 --profile=<profile> getsids -p <pidofprocess> > getsids-results.txt
  ```

  ### Hibernation file to memdump

  A hibernation file is stored in C:\hiberfile.sys if you have hibernation enabled. It contains parts of the memory at the time of hibernation, depending on the version of Windows. Run this to covert it
  to a raw image for further processing with Volatility.

  ```bash
  volatility -f /path/to/hiberfile.sys --profile=<profile> imagecopy -O /path/to/output/folder/hibermemory.ra
  ```

  ## Super timeline

  Timeline of events + MFT entries

  ```bash
  # First generate the plaso dump
  log2timeline.py plaso.dump /path/to/drive/image.E01
  psort.py -z "America/Sao_Paulo" -o L2tcsv /path/to/plaso.dump -w plaso.csv "date > 'yyyy-mm-dd hh:mm:ss' AND date < 'yyyy-mm-dd hh:mm:ss' "
  
  # Using docker
  sudo docker pull log2timeline/plaso
  sudo docker run -v $(pwd):/data log2timeline/plaso log2timeline /data/plaso.dump /data/image.E01 # Supposing that the E01 file is in your current directory
  sudo docker run -v $(pwd):/data log2timeline/plaso psort -z "America/Sao_Paulo" -o L2tcsv /data/evidence.plaso "date > 'yyyy-mm-dd hh:mm:ss' AND date < 'yyyy-mm-dd hh:mm:ss'" -w /data/evidence.csv
  ```

  You can filter out some temporary internet files, as these tend to add a lot of noise. The suggested ones to exclude are:

```
  - Temporary\ Internet \Files
  - PrivacIE
  - Content.IE5
  - IETldCache
  - ACPI
  - MSIE\ Cache\ File
  - THREAD
  - \(\$FILE\_NAME \)
  - DLL\ LOADTIME
```
  You can store these in a whitelist file and then do negative grep to filter them out.

  ```bash
  grep -a -v -i -f whitelist.txt /path/to/plaso.csv > supertimeline.csv
  ```

  ## Timeline with memory dump + disk

  ```bash
  $ fls -m -p -r /path/to/image.E01 -i ewf > drive-image-timeline-bodyfile
  $ volatility -f /path/to/image.001 --profile=<profile> timeliner --output=body --output-file=drive-image-timeline-timeliner.body
  $ cat drive-image-timeline-timeliner.body >> drive-image-timeline-bodyfile
  $ mactime -z America/Sao_Paulo -y -d -b drive-image-timeline-bodyfile <start time..end time in format yyy-mm-dd..yyyy-mm-dd> > drive-image-memory-timeline.csv
  # This will give you a timeline with all the events in the given period.
  ```

  ## Windows event log

  **Location** 

  ≥ Windows 7/2012 ⇒ `C:\Windows\System32\winevt\*.evtx`
  `C:\Windows\System32\config\*.evt`

  **Tools**

  - [Event Log Explorer](https://eventlogxp.com/) (evt/etvx)
      - `Correcting UTC: View -> Time Correction -> Display UTC time`
  - [evtxecmd](https://ericzimmerman.github.io/) (evtx only)

### Event IDs

**Remote Desktop - RDP** - *Source*
  **Security**
  - 4776 – Account logon with local authentication
  - 4624 – Account logon with domain authentication
    - Logon Type 10 is RDP interactive session
  - 4625 - Failed account login attempt
  - 4648 - Logon specifying alternate credentials - if NLA enabled on destination.
    - Current logged-on
    - User Name
    - Alternate User
    - Name Destination
    - Host Name/IP
    - Process Name
  - 4688 - Process spawn
    - Text search for psexec, mimikatz, powershell, wmic, IEX.
  - 4778/4779 – RDP reconnects
  - 5140 – Shares mounting
  - 7045 – Service installation

  **Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx**

  - 1024 - Destination Host Name
  - 1102 - Destination IP Address

  **Map Network Share (net.exe)**

  *Source*

  **Security.evtx**

  - 4648 – Logon specifying alternate credentials
    - Current logged-on
    - User Name
    - Alternate User
    - Name Destination
    - Host Name/IP
    - Process Name

  **Microsoft-Windows-SmbClient%4Security.evtx** 

  - 31001 – Failed logon to destination
    - Destination Host Name
    - User Name for failed logon
    - Reason code for failed destination logon (e.g. bad password)

  *Destination*

  **Security.evtx**

  - 4624 - Logon Type 3
    - Source IP/Logon
    - User Name
  - 4672
    - Logon User
    - Name Logon by user with administrative rights
    - Requirement for accessing default shares such as C$ and ADMIN$
  - 4776 – NTLM if authenticating to Local System
    - Source Host Name/Logon User Name

  **Timeline of event files**

  ```powershell
  # Single file
  EvtxECmd.exe -f C:\Path\to\Security.evtx --csv C:\Path\to\directory\of\logs
  # Directory containing events
  EvtxECmd.exe -d C:\Path\to\events --csv C:\Path\to\directory\of\logs
  ```

  **Always** change the timezone when visualizing the data from EvtxECmd.exe, default is UTC-0. In excel, create a new column and use this formula: 
  `=A2 - (3/24)` ⇒ Converting UTC-0 to UTC-3

  ## Plaso filters

  Useful for collecting only useful information from an image

  ```bash
  $ cat filter.txt
  /[$]Recycle.Bin/.+
  /Users/.+/NTUSER.DAT
  /Users/.+/AppData/Local/Google/Chrome/.+/.+/.+
  /Users/.+/AppData/Local/Google/Chrome/.+/.+/.+/.+
  /Windows/System32/config/SOFTWARE
  /Windows/System32/config/SYSTEM
  /Windows/System32/config/SAM
  /WIndows/System32/config/SECURITY
  /Windows/System32/config/WinEvt/Logs/.+
  /Windows/System32/WinEvt/Logs/.+
  /[$]MFT
  /[$]Extended/.+
  /Windows/AppCompat/Programs/Amcache.hve
  /Windows/Prefetch/.+
  /Windows/System32/Tasks/.+
  $ log2timeline --filter_file filter.txt --parsers triage image-plaso.dump </path/to/image.E01>
  ```

  **Browser history**

  Edge and Internet explorer:

  - `C:\Users\username\AppData\Local\Packages\Microsoft.MicrosoftEdge_\AC\MicrosoftEdge\User\Default\Favorites`
  - `C:\Users\username\AppData\Local\Packages\Microsoft.MicrosoftEdge_\AC\MicrosoftEdge\User\Default\Recovery`
  - `C:\Users\username\AppData\Local\Packages\Microsoft.MicrosoftEdge_\AC\MicrosoftEdge\User\Default\DataStore`
  - `C:\Users\username\AppData\Local\Microsoft\Windows\WebCache`
  - `C:\Users\username\AppData\Local\Microsoft\Windows\History`
  - `C:\Users\username\AppData\Local\Microsoft\Internet Explorer\IECompatData\`
  - `C:\Users\username\AppData\Local\Microsoft\Feeds Cache\`
  - `C:\Users\username\AppData\Local\Microsoft\Windows\WebCache\`
  - `C:\Users\username\AppData\Local\Microsoft\Windows\Temporary Internet Files\`

  **Chrome**

  - `C:\Users\username\AppData\Local\Google\Chrome\User Data\Default\History`

  Firefox

  - `C:\Users\username\AppData\Roaming\Mozilla\Firefox\Profiles\`

## PCAP Analysis

NetworkMiner for statistics of DNS queries, long connections, amount of traffic of each IP.
TODO

## Malware analysis

**OSINT lookup**

[https://www.virustotal.com/gui/home/search](https://www.virustotal.com/gui/home/search)

[https://totalhash.cymru.com](https://totalhash.cymru.com/)
[https://metadefender.opswat.com/#!/](https://metadefender.opswat.com/#!/)
[https://avcaesar.malware.lu/](https://avcaesar.malware.lu/)
[https://malwr.com/](https://malwr.com/)
[https://hybrid-analysis.com](https://hybrid-analysis.com)
### Signature check
Beware! It sends the file to VT!
Tool: [https://docs.microsoft.com/en-us/sysinternals/downloads/sigcheck](https://docs.microsoft.com/en-us/sysinternals/downloads/sigcheck)

```=powershell
sigcheck -c -e -u -h -v -vt filename.exe > sigcheck-results.csv
sigcheck -c -e -u -h -v -vt \path\to\folders\like\system32 > sigcheck-results.csv
```

Open the CSV in Excel and order by the VT detection column to see which files had VirusTotal trigger.

## Data carving
Some tools
- scalpel / foremost
- [photorec](https://www.cgsecurity.org/wiki/TestDisk_Download)
Extract files from unallocated space/slack space
```bash
blkls <image.E01> > image.blkls
```
Then run foremost as the data carving tool, to look for file structures eaders, footers, magic bytes etc) in the image you made with blkls:
```bash
foremost -q -b 4096 -o <output directory> -c /usr/local/etc/foremost.conf age.blkls
```

LCP - Check if account has password, found [here](https://www.youtube.com/watch?v=NG9Cg_vBKOg&ab_channel=HackersOnBoard&s=4350)

https://www.lcpsoft.com/en/index.html

---
## Linux/Unix
TODO!

Volatility cheatsheet



---
## 📖 Incident Response Methodology
TODO!

---
# Live response
Checking for security updates with [MBSA](https://www.microsoft.com/en-us/download/details.aspx?id=19892) scan
```powershell
wmic qfe where hotfixid="KB958644" list full
# Remotely querying for hotfixes
wmic qfe where hotfixid="KB958644" list full /node:127.0.0.1 /user:admin /password:p@ssw0rd
```
## DHCP
Default Location Windows 2003/2008/2012 => %windir%\System32\Dhcp

**Enable DHCP logging**
```powershell
reg add HKLM\System\CurrentControlSet\Services\DhcpServer\Parameters /v tivityLogFlag /t REG_DWORD /d 1
```
---
## DNS
**Enable DNS logging**
```powershell
DNSCmd <DNS SERVER NAME> /config /logLevel 0x8100F331
```
**Setup path log**
```powershell
DNSCmd <DNS SERVER NAME> /config /LogFilePath <PATH TO LOG FILE>
```
**Set max size**
```powershell
DNSCmd <DNS SERVER NAME> /config /logfilemaxsize 0xffffffff
```
### **Powershell way** (Requires [RSAT](http://www.microsoft.com/en-/download/details.aspx?id=7887](http://www.microsoft.com/en-/download/details.aspx?id=7887)))
**Check if module is installed**
```powershell
Get-Module DNSServer –ListAvailable
```
**Check whats is enabled**
```powershell
Get-DnsServerDiagnostics
```
**Enable all diagnostic options except for LogFilePath**
```powershell
Set-DnsServerDiagnostics -All $True
```
**Enable diagnostics for outgoing TCP responses for updates**
```powershell
Set-DnsServerDiagnostics -SendPackets $True -TcpPackets $True -Answers rue -Updates $True
```
**Show usage**
```powershell
Get-Help Set-DnsServerDiagnostics
```
---
**Show process running**
```powershell
# cmd
tasklist
# Using WMI
wmic process list full
```
**Accounts avaliable**
```powershell
net user
net localgroup administrators
```
**Users logged on**
```powershell
psloggedon \\computername
quser
```
**Date of creation ⇒ new accounts**
```powershell
wmic useraccount get name,localaccount,installdate
# One approuch is check creation time of folder directory
dir /tc "C:\Documents and Settings\"
dir /tc "C:\Users\"
# /t = time
# /c = creation
# Other is looking at the events log file (Windows XP/2003)
cscript c:\windows\system32\eventquery.vbs /L security /FI "id eq 642"
# >= Windows 7
wevtutil qe security /f:text "/q:*[System[(EventID=4720)]]" | more
```
**Show all ports allowed in the firewall**
```powershell
netsh firewall show portopening
```
**Open sessions**
```powershell
net view \\127.0.0.1
net session
nbstat
netstat -nabo
```
**Startup applications**
```powershell
wmic startup list full
```
# Linux/Unix
**Check for process running**
```bash
ps -ef
ps aux
# Info about specific process, as ports and files associated
for i in $(pgrep processo-malicioso); do lsof -p $i; done
```
**Searching for files**
```powershell
# Owned by root
find / -uid 0 -perm -4000 –print
# By size - greater than 10 mb
find / -size +10M –ls
# By time modification - between date A and B, ex: 10-10-2019 until 20-10-19
find / -newertime 'yyyy-mm-dd' ! -newertime 'yyyy-mm-dd'
```
**Check for connections**
```powershell
netstat -tupan
# Listening ports
ss -lntp
# Live monitoring of ports
ss -ltnp | less -S
# Arp table
arp -a
```
**Check for allowed firewall rules**
```bash
iptables -t nat -nL
iptables -t mangle -nL
iptables -t filter -nL
iptables -t raw -nL
```
**Scheduled jobs**
```bash
# Current user
crontab -l
# User specific
sudo crontab -u id3s3c
```

---
### Analysis of Competing Hypotheses (ACH)

Analysis to help validate a set of possible hypotheses for RCA (root cause analysis) after an incident.

1. Create a list of hypotheses that are possible causes.
2. Create a list of evidences gathered during the investigation.
3. Create a matrix where the columns are the hypotheses and the rows are evidences.
4. Evaluate line by line if the evidence is: `C` - consistent, `I` - inconsistent or `A` - ambiguous if the hypotheses is true or false.
5. Delete/Hide evidence that is consistent with all hypotheses.
6. Assess each evidences reliability (A-F) and credibility/truthness (1-6)
    * Who or what was the source of this evidence?
    * What access the source have?
    * What is the source reliability?
    * Is the information plausible?
7. Rank the hypotheses in terms of least disconfirming evidence (rather than most supporting evidence )
    * Least evidence against is more likely to be correct.
        - Remote
        - Very unlikely
        - Unlikely
        - Even chance
        - Probably/likely
        - Very likely
        - Almost certainly

| Reliability   | Meaning                    |
| ------------  | -------------------------  |
| `A`           | Completely reliable        | 
| `B`           | Usually reliable           |
| `C`           | Fairly reliable            |
| `D`           | Not usually reliable       |
| `E`           | Unreliable                 |
| `F`           | Reliability can't be judge |

-------------------------------------------

| Credibility   | Meaning                    |
| ------------  | -------------------------  |
| `1`           | Confirmed by other sources | 
| `2`           | Probably true              |
| `3`           | Possibly true              |
| `4`           | Not usually reliable       |
| `5`           | Improbable                 |
| `6`           | Truth can't be judge       |

-------------------------------------------

### Wannacry Example - Who was responsible for the attack?

H1 - A sophisticated financially-motivated cybercriminal actor
H2 - An unsophisticated financially-motivated cybercriminal actor
H3 - A nation state or state-affiliated actor conducting a disruptive operation
H4 - A nation state or state-affiliated actor aiming to discredit the National Security Agency (NSA)

| Evidence | H1 | H2 | H3 |
| -------- | -- | -- | -- |
|          | C  | C  | I  |



**References**
https://www.youtube.com/watch?v=iuU_GI5WMpY
https://isc.sans.edu/forums/diary/Analysis+of+Competing+Hypotheses+WCry+and+Lazarus+ACH+part+2/22470/
https://www.reliaquest.com/blog/wannacry-an-analysis-of-competing-hypotheses-part-ii/

---

## Useful information
- [Spreadsheet with information about ransomware](https://docs.google.com/spreadsheets/d/e/2PACX-1vRCVzG9JCzak3hNqqrVCTQQIzH0ty77BWiLEbDu-q9oxkhAamqnlYgtQ4gF85pF6j6g3GmQxivuvO1U/pubhtml#) [provided by the community](https://docs.google.com/spreadsheets/d/e/2PACX-1vRCVzG9JCzak3hNqqrVCTQQIzH0ty77BWiLEbDu-q9oxkhAamqnlYgtQ4gF85pF6j6g3GmQxivuvO1U/pubhtml#)

## References
- https://blog.1234n6.com/2018/10/available-artifacts-evidence-of.html
- https://digital-rensics.sans.org/community/papers/gcfa/windows-logon-forensics_6928
- https://github.com/christophetd/hunting-ndmaps/blob/master/pdf/windows-basic-event-logs.pdf
- https://github.com/christophetd/hunting-ndmaps/blob/master/pdf/memory-hunting.pdf
- https://github.com/EricZimmerman
- https://www.sans.org/blog/finding-unknown-malware-with-densityscout
- https://digital-forensics.sans.org/media/DFPS_FOR508_v4.6_4-19.pdf
- https://www.sans.org/blog/help-improve-edd-encrypted-disk-detector/
- http://dragon-online.net/ (Firefox said that there is **cryptominer** running here, be aware)
- https://www.youtube.com/c/SANSDigitalForensics
- https://digital-forensics.sans.org/media/rekall-memory-forensics-eatsheet.pdf
- https://www.andreafortuna.org/2018/06/04/using-mft-anomalies-to-spot-spicious-files-in-forensic-analysis/
- https://www.sans.org/reading-room/whitepapers/incident/incident-ndlers-handbook-33901
- https://docs.microsoft.com/en-us/powershell/module/dnsserver/set-sserverdiagnostics?view=win10-ps
- https://www.securitynik.com/

SANS Posters
    - https://www.sans.org/security-resources/posters/dfir-find-evil/35/download
    - https://in-addr.nl/mirror/SANS-Digital-Forensics-and-Incident-Response-Poster-2012.pdf
    - 
