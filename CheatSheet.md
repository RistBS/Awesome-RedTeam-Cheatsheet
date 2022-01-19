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
    - [PrivExchange]()
    - [ProxyLogon]()
    - [CVE-2020-0688]()
  - [Forest Persience]()
    - [DCShadow]()
  - [Cross Forest Attacks](#cross-forest-attacks)
    - [MSSQL Server](mssql-server)
      - [UNC Path Injection](unc-path-injection)
      - [SSRP/MC-SQLR Poisoning](ssrpmcsqlr-poisoning)
      - [Persistence]()
        - [DML, DDL & Logon Triggers]()
     - [Trust Tickets](#trust-tickets)
  - [Miscs](#miscs)
    - [Domain Level Attribute](#domain-level-attribute)
      - [MachineAccountQuota (MAQ) Exploitation](#machineaccountquota-maq-exploitation) 
    - [Abusing IPv6 in AD](#abusing-ipv6-in-ad)
      - [IOXIDResolver Interface Enumeration](#ioxidresolver-interface-enumeration)


## Miscs :

### Domain Level Attribute :

#### MachineAccountQuota (MAQ) Exploitation :

use crackmapexec (CME) with maq module :
```sh
cme ldap $dc -d $DOMAIN -u $USER -p $PASSWORD -M maq
```

### Abusing IPv6 in AD :

#### IOXIDResolver Interface Enumeration

it's a little script that enumerate addresses in NetworkAddr field with RPC_C_AUTHN_DCE_PUBLIC level
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

