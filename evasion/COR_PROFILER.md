un attaquant peut exploiter la variable d’environnement COR_PROFILER pour détourner le flux d’exécution des programmes qui chargent le **CLR .NET**. 
**COR_PROFILER** est une fonctionnalité du **.NET Framework** qui permet aux développeurs de spécifier **un fichier DLL** à charger dans chaque processus .NET qui charge le Common Language Runtime (CLR). Ces profileurs sont conçus pour surveiller, dépanner et déboguer le code managé exécuté par le CLR .NET.



COR_PROFILER : si la vérification COR_ENABLE_PROFILING réussit, le CLR se connecte au profileur qui a ce CLSID ou ProgID, 
lequel doit avoir été stocké précédemment dans le Registre. La variable d'environnement COR_PROFILER est définie en tant que chaîne, comme indiqué dans les deux exemples suivants.



![image](https://user-images.githubusercontent.com/75935486/151682546-e798b414-4757-4ab6-9e30-2b863024dddf.png)





**Références :**

- https://attack.mitre.org/techniques/T1574/012/
