
![](https://github.com/RistBS/Active-directory-Cheat-sheet/attack-kill-chain-small.jpg)

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
