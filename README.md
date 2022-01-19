This AD attacks CheatSheet, made by RistBS is inspired by the [Active-Directory-Exploitation-Cheat-Sheet](https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet) repo.


<a href="https://ibb.co/z7DSpds"><img src="https://i.ibb.co/pR53cq2/attack-kill-chain-small.jpg" alt="attack-kill-chain-small" border="0" /></a>

# Active-directory-Cheat-sheet
## Summary

- [AD Exploitation Cheat Sheet by RistBS](#active-directory-exploitation-cheat-sheet)
  - [Summary](#summary)
  - [Tools](#tools)
  - [Hash Cracking]()
  - [Enhanced Security Bypass]()
    - [AntiMalware Scan Interface (AMSI)]()
    - [ConstrainLanguageMode (CLM)]()
    - [Just Enough Administration (JEA)]()
    - [ExecutionPolicy (EP)]()
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
john --format=lm hash.txt
hashcat -m 3000 -a 3 hash.txt

NT : 
john --format=nt hash.txt --wordlist=wordlist.txt
hsahcat -m 1000 -a 3 hash.txt


NTLMv1 :

using JTR :
```bash
john --format=netntlmv1 hash.txt
```
using hashcat :
```bash
hashcat -m 5500 --force -a 0 hash.txt wordlist.txt
```

NTLMv2 :

using JTR :
```bash
john --format=netntlmv2 hash.txt
```
using hashcat :
```bash
hashcat -m 5600 --force -a 0 hash.txt wordlist.txt
```

Kerberoasting :

using JTR :
```bash
john --format=krb5tgs spn.txt --wordlist=wordlist.txt 
```
using hashcat :
```bash
hashcat -m 13100 -a 0 spn.txt wordlist.txt --force
```

ASREPRoasting :
```bash
hashcat -m 18200 -a 0 hash wordlist.txt --force
```

note : some Hash Type in hashcat depend of the **etype**

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

it's a little script that enumerate addresses in NetworkAddr field with **RPC_C_AUTHN_DCE_PUBLIC** level
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
