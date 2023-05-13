
---

![image](https://user-images.githubusercontent.com/75935486/197309013-e3bcee09-6981-4a31-9eba-c585dd856ae8.png)


---

- [Intro to OPSEC](#intro-to-opsec)
- [Our Ennemies](#our-ennemies)
- [Offensive Architecture](#offensive-architecture)
- [Information Gathering](#information-gathering)
- [Security Events](#security-events)
- [OPSEC or Not ?](#opsec-or-not-)
- [OPSEC Tips](#opsec-tips)
  - [Kerberos Attacks](#kerberos-attacks)
  - [Pivoting](#pivoting)
  - [Tooling & Malwares](#tooling--malwares)



## Intro to OPSEC

the term OPSEC is first used in the U.S Army and then in cybersecurity. OPSEC in red team means mainly the fact to be more discreet, it implies to [understand the methods](https://github.com/TonyPhipps/SIEM) used by the blue teamers to better anticipate them.
 
it's important to know that OPSEC is a large term and depends of the situation, Blue Team (SIEM/IR), Equipment/Security Products, Environment, the vigilance of the employees/users of the company and of course, it will depends of YOU !

> with a little bit of OSINT you can easily find out which security products are used by the company, who are the employees, ect... So you can adapt and opt for more optimal strategies.

## Our Ennemies

- **EDR & Monitoring Products**: Elastic EDR, Cortex EDR/XDR, Sentinel One (S1) EDR, Crowdstrike EDR, SigmaHQ, Azure-Sentinel, Splunk, FalconForce, MDE
- **Memory IOC Scanner**: malfind, PE-sieve, Moneta, BeaconHunter, Hunt-Sleeping-Beacons, MalMemDetect
- **Pattern Matching**: YARA, BeaconEye, Crowdstrike Falcon X, CAPA, SIGMA

If we go a bit deeper in defenses used on windows environment we can see these : 

- **UM Hooks** - hooks placed by EDRs, the works of theses is to redirect it into

- **Kernel Callbacks** - (e.g. `PspCreateProcessNotifyRoutine` for process creation, `PspCreateThreadNotifyRoutine` for thread creation or `PspLoadImageNotifyRoutine` for image loading)

ETW includes ETW providers, the most revelant providers are :
```
Microsoft-Antimalware-Scan-Interface     {2A576B87-09A7-520E-C21A-4942F0271D67}
Microsoft-Windows-PowerShell             {A0C1853B-5C40-4B15-8766-3CF1C58F985A}
Microsoft-Antimalware-Protection         {E4B70372-261F-4C54-8FA6-A5A7914D73DA}
Microsoft-Windows-Threat-Intelligence    {F4E1897C-BB5D-5668-F1D8-040F4D8DD344}
```
- The `Microsoft-Windows-Threat-Intelligence` provider corresponds to ETWTI, an additional security feature that an EDR can subscribe to and identify malicious uses of APIs (e.g. process injection).



as I said at the beginning it is also important to understand how a blue teamer can catch us, here is what a blue teamer often does :
 - Hardening the environment (patching, logging...)
 - Monitoring unusual behaviour (IOCs, suspicious activity...)
 - Responding to incidents (system isolation, account lockouts...)
 - Investigating the origin of those incidents (forensics traces, artifacts...)

### Data Sources

![](https://user-images.githubusercontent.com/75935486/208495258-ca933a0f-a775-46a4-819e-e244e490701d.PNG)


> I recommand this talk ["Quantify Your Hunt: Not Your Parents' Red team - SANS Threat Hunting Summit 2018"](https://www.youtube.com/watch?v=w_kByDwB6J0&ab_channel=AdrianCrenshaw) if you want to learn more about hunting.



## Offensive Architecture

Blue Teamers often looks at Network Indicators for suspicious network activity within systems with ETW (Microsoft-Windows-Winsock-AFD, Microsoft-Windows-TCPIP…), Callbacks (WskAcceptEvent, WskReceiveEvent…), IDS/IPS solutions, WAFs, corporate proxies…

Relevant network indicators :
- Traffic inspection
  - SSL/TLS inspection
- Domains and IPs accessed
  - Domain categorization? Cert information? Weird names?
- Amount of traffic
- Processes beaconing
  - Fixed times



### Communications

let's talk a bit about communications. Mosts known protocol for the communication is HTTP because it can be very malleable to mimic a real application/website comms. (e.g. : Avast Agent, Microsoft Teams, Wikipedia...) or simply hide some suspicious traces. Other protocols Wireguard, DNS, DoH, ect... are very good too and offer many other possibilites to hide from defenders. Encryption can also be used such as SSL/TLS/mTLS, ect... 

If you want to expand your infrastructure, you can deploy others Instances like AWS EC2, S3 Buckets ect... 
Redirectors to hide your real servers. 


## Information Gathering



### Internal Recon


### External Recon

#### OSINT



## Security Events

mainly handled with Sysmon on windows

### Most known Security Events

an Event ID (EID) represents an action performed by application, host, ect... On the network. EID has fields filled with some additional informations, It can be used in queries (WQL, AQL, EQL...) and combined to be more precise. Here is some known EID :

- EventID 3 (NetworkConnect) : this event can be used by defenders to detect malicious traffic 
- EventID 17 (PipeCreate) & EventID 18 (PipeConnect) : mostly used to detect named pipe pivoting with EID 3
- EventID 4698 & EventID 4699 : A Scheduled Task was created/ Scheduled Task was deleted (often used for schtasks persistence)
- EventID 4703 () : token privileges manipulation (can also be used to detect token stealing)


## OPSEC or Not ?

- **Usage of cmdline :** 

that's a big no, you can always [obfuscate command lines](https://www.wietzebeukema.nl/literature/Beukema,%20WJB%20-%20Exploring%20Windows%20Command-Line%20Obfuscation.pdf) by using substitutions like Unicode, Greek, Latin Extended-A/Extended-B but it's not very effective. To avoid suspicious Cmdline you can do [command line spoofing](https://github.com/matthieu-hackwitharts/Win32_Offensive_Cheatsheet#command-line-spoofing) The best way to avoid the shell is to use native C2 commands and use the WinAPI to perform other actions (for example, instead of using `vssadmin` or `wmic` to remove shadow copies, use the **IVssCoordinator** COM interface). As for powershell, I don't recommend using it at all, you can use an unmanaged version of powershell (e.g. : Cobalt Strike's powerpick), but even so, it'll still be risky.



- **Dropping File on Disk vs Execution In-Memory :** 

It's well known that dropping files on the disk is not opsec safe. Nevertheless, we can download a file in less verified directories, being part of an exclusion or `C:\temp`.

In-Memory executions can load .NET binaries into memory, it has has sub-techniques such has `inline-execute-assembly`, `inproc-execute-assembly` bring into NightHawk C2 or even `inline-execute-assembly` working with sleep obfuscation developped for Havoc C2. But don't forget about CLR UsageLogs. you can also run PE in-memory with RDLL, COFF Loader...

- **Opening a New Process :** 

No, process handles objects are very closely monitored (and it's also monitored by windows defender since 11/18/2022). The best way is to reuse opened handles.


- **Injecting our shellcode into a remote process :**

<br>

## OPSEC Tips

### Kerberos Attacks

> ***OPSEC Tip* : RC4 is deprecated compared to AES, instead of PTH attack, use Overpass The Hash attack using Kerberos AES256 ekeys.**

> ***OPSEC Tip* : when you are doing DCsync, if replication are made between Computer and DC you could get caught, so you always have to do a DCSync from a DC to DC.**

#### ASREPRoasting

ASREPRoasting can be detected because it generates [Event ID 4768](), this EID means that a TGT was requested. Defenders will focus on Tickets with 0x17 (RC4) Encryption.

#### Kerberoasting

Kerberoasting attack still very noisy and could generate Event ID 4769, defenders can also based they analysis on requests with RC4 encryption (0x17).

if you use impacket to do kerberoasting, there is a tool called [orpheus](https://github.com/trustedsec/orpheus) allows you to fully customize your TGS-REQ by modifing encryption and `kdc-options` fields to bypass some restrictions/protection relied to kerberoasting. Whereas if you use rubeus directly on the machine you can use filters like `/spn` to roast a specific SPN or `/user` to roast a specific user.


> last note on tools because mimikatz leaves traces like timestamp

### Pivoting

> ***OPSEC Tip* :  Proxy every remote action you can using SOCKS proxy with [proxifier](https://proxifier.com/docs/win-v4/) for example.**


#### SMB named pipe pivoting

custom SMB pipe name would get picked up in Sysmon **Event ID 17** and **Event ID 18** as a known IoC. Most of the rules are based on threat actor groups, C2 default named pipe, or known tools. For instance : 
- SolarWinds SUNBURST Named Pipe Detection : `'\\583da945-62af-10e8-4902-a8f205c72b2e'`
- Cobalt Strike C2 Named Pipe Detection : `'\\MSSE-'`, `'\\postex_ssh_'`, `'\\postex_'`
- PsExec Tool Named Pipe Detection : `'\\psexec'`, `'\\paexec'`, `'\\remcom'`, `'\\csexec'`

> ***OPSEC Tip* : you can [check for open named pipes](https://github.com/RistBS/test/blob/main/README.md#enumeration) on the target and use the one which is not detected yet using a malleable profile if your C2 support it or whatever.**

### Tooling & Malwares

> ***OPSEC Tip* : Take in consideration every sides of a technique, the best thing to illustrate that is the [Capability Abstraction](https://posts.specterops.io/capability-abstraction-fbeaeeb26384)**



#### Languages

Choose a language that fully support the WinAPI and perform memory management so low level languages is prefered.

the CIA recommended that a malware should be under 150KB
- Rust - 600KB
- Golang - 1.9MB
- Nim - 70KB
- C - 11KB


#### Entropy

- entropy is a measure of randomness, the entropy of a file is a good indicator to detect potential malwares, there's a formula of entropy defined by Shannon where $p(x)$ is the frequency of byte $x$ in the file: 

$${\sum_{x∈{{0,..,255}}}P(x)\log(p(x))}$$ 

> ***OPSEC Tip* : you can trick this indicator using compression, arrays populated with `0`...**

*other indicators can be used to detect malicious tools like mimikatz and his timestamp*

#### Morph your malwares & tasking

> ***OPSEC Tip* : Touching to NTDLL or Kernel32 is pretty bad OPSEC, the better ways is to refresh the module in memory.**

> ***OPSEC Tip* : Avoid RWX memory permissions, RW->RX is better :D**

> ***OPSEC Tip* : Avoid suspicious Parent/child relationships with [PPID Spoofing](https://github.com/matthieu-hackwitharts/Win32_Offensive_Cheatsheet#ppid-spoofing)**

> ***OPSEC Tip* : Direct syscall execution can get caught, a better way is to mask your syscalls with `nop` instructions or avoid using `syscall` instruction**

> ***OPSEC Tip* : Be careful of which techniques can be turned into an IoC, for example patching in memory `AmsiScanBuffer` is good in one side because it's stops AMSI Scanning but in another side, touching memory is very agressive, a better ways is to uses hardware hooks.**



## Credits

- [@_RastaMouse](https://twitter.com/_RastaMouse) - https://www.youtube.com/watch?v=qIbrozlf2wM&ab_channel=CyberV1s3r1on
- [@ATTL4S](https://twitter.com/DaniLJ94) & [@ElephantSe4l](https://twitter.com/ElephantSe4l) - https://www.slideshare.net/DanielLpezJimnez1/understanding-and-hiding-your-operations
- [@rad9800](https://twitter.com/rad9800) - https://www.youtube.com/watch?v=TfG9lBYCOq8&ab_channel=SteelCon
- [@inf0sec](https://twitter.com/inf0sec1) - for the proofreading of a red team pov
- [@Dysnome](https://twitter.com/Dysnome_Be) - for the proofreading of a blue team pov

### Recommendations

- https://www.youtube.com/watch?v=StSLxFbVz0M&ab_channel=DEFCONConference - a review of APT's OPSEC fails 
