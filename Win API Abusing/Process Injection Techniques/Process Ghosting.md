**I - Introduction :**

Tout comme les autres techniques de **Process Injection**, le Process Ghosting est une techniques permettant de bypass des AV et des endpoints, 
cette techniques est récentes et reste similaire aux techniques précedentes comme le Process **Doppelganging** et **Herpaderping**

**Procédé :** 

![](https://images.contentstack.io/v3/assets/bltefdd0b53724fa2ce/blt930f0b0e46dd0d53/60aeb7b447ebc9669e1e8174/4-blog-process-ghosting.png)





**II - étape :**

- **1 :** **Créer** un fichier
```c
h = CreateFile()
```
- **2 :** Placez le fichier dans un état **en attente de suppression (Delete-Pending State)** à l’aide de `NtSetInformationFile(FileDispositionInformation)`
on peut également utilisé `FILE_DELETE_ON_CLOSE`.
- **3 :** **Écrivez** le payload dans le fichier. Le contenu n’est pas conservé car le fichier est déjà en attente de suppression. L’état en attente de suppression bloque également les tentatives d’ouverture de fichier externe.
```c
WriteFile(h)
```
- **4 :** **Créez** une section d’image pour le fichier.
- **5 :** **Fermez** le descripteur en attente de suppression en **supprimant le fichier**.
- **6 :** **Créez un processus** à l’aide de la section image.
- **7 :** **Affectez** des arguments de processus et des variables d’environnement.
- **8 :** **Créez un thread** à exécuter dans le processus.
```c
CreateThreadEx() -> CreateProcessEx()
```

on peux exploiter le proc ghosting via [kinghamlet](https://github.com/IkerSaint/KingHamlet) qui a la possibilité de chiffré en AES, nous pouvons aussi y exploiter avec la [technique traditionnelle](https://github.com/hasherezade/process_ghosting)

![image](https://user-images.githubusercontent.com/75935486/151682211-d276ce18-afa8-43fb-bddf-23462af9a0a7.png)



Fonction CreateFile() :

![image](https://user-images.githubusercontent.com/75935486/151682187-2b675d9c-5e4e-4cd1-a215-0cbce12efc13.png)

Delete Pending State :

![image](https://user-images.githubusercontent.com/75935486/151682372-0ae10ef6-f51d-48fb-ba92-1b728881713f.png)



Réferences :
- https://github.com/IkerSaint/KingHamlet
- https://www.elastic.co/fr/blog/process-ghosting-a-new-executable-image-tampering-attack
- https://github.com/hasherezade/process_ghosting
