


#### **1. Les registres :**

![image](https://user-images.githubusercontent.com/75935486/152057010-ffd64c4f-8fa1-4f5f-8d24-280548268268.png)






#### **2. Sections :**

- .text : contient le code c'est à dire les instructions qui consistent le programme lui-même. Il est marqué comme exécutable et en lecture seule (r-x).
- .data – qui est utilisé pour stocker des variables statiques et globales (les variables non statiques sont stockées sur la pile). Il est marqué comme lecture-écriture et non exécutable (rw-).
- .bss – qui stocke des variables non initialisées. Il est marqué comme lecture-écriture et non exécutable (rw-).
- .rodata – qui stocke des données constantes. Il faut s’attendre à ce que des strings et d’autres valeurs constantes  soit stocké dans rodata. c'est pour une lecture seule.

![image](https://user-images.githubusercontent.com/75935486/152057979-7f6a2028-b03f-4a7e-9058-3cb43960a1ee.png)



#### **3. les tailles de données :**

- db = define bytes (8 bits)
- dw = define word (16 bits) 
- dd = define double word (32 bits)


#### **4. Instructions de base :**

- jmp : jump vers une étiquette call : appelle les instructions d'une étiquette
- movzx/movsx: movzx permet la conversion des nombres naturels en plus grand format alors que movsx le fais pour des nombres entiers. 
- mov 'destination', 'source' (valeur dans regsitre)
- sub : soustraction 
- add : addition 
- div : division 
- xor: XOR ce base sur sa table de vérité: `1 et 1 = 0` / `0 et 1 = 1`
- rol/ror: rotation de bits l=left et r=right 
- mul/imul: imul effectue une multiplication signée alors que mul peux uniquement sur du non-signé soit entièrement Positive
- pop : dépile dans la stack 
- push : empile en haut de la stack
- syscall: appel système 
- ret : return 
- inc : incrémentation de 1 
- loop équivalent à while, c'est une boucle. 
- lea : Cette instruction permet d'incrémenter un registre ou un emplacement mémoire.


#### **5. Hello World ! : **

```asm
BITS 64

global start ; commence à start

section .rodata
    hello db "Hello World !", 0xa, 0x0 ; le str "hello world" avec 0xa pour le saut de ligne
    hello_lengh equ $-hello ; calcul de la taille
    
section .text ; démarrage du code

start: ; label start
      mov rax, 0x1 ; mettre 1 dans rax ( sorti standard )
      mov rdi, 0x1 ; mettre 1 dans rdi
      mov rsi, hello ; mettre le str hello dans rsi
      mov rdx, hello_lengh ; mettre la taille (lengh) de hello dans rdx
      syscall ; appel systeme pour charger le bloc d'instruction avec la sorti standard
      jmp exit ; jump vers exit
      
exit:
      mov rax, 0x3c ; appel du syscall 60, le mettre dans rax
      xor rdi, rdi ; mettre rdi à 0 via xor
      syscall ; appel systeme
```

###### 5.1 Compilation :
```
nasm -f elf64 -o hello.o hello.asm && ld -o hello hello.o
```

#### **6. Sauts Conditionnels**

- JE : saut si égal
- JZ : saut si résultat est zéro
- JG : saut si plus grand
- JEG : saut si plus grand ou égal (equal or above)
- JL : saut si plus petit (less)
- JC : saut si retenue (carry)
- JNO : saut si pas déborbement (not overflow)
- ...

#### **7. boucles**

si on considère cette boucle `for (cx=0; cx<5; cx++){ ax = ax + cx }`, en assembleur sa ressemblerais à ça :

```asm
xor rax, rax 
xor rcx, rcx

boucle:
    cmp rcx, 0x5
    jge done
    add rax, rcx 
    inc rcx 
    jmp boucle 
done:
     mov rax, 0x3c
     xor rdi, rdi
     syscall
```
 on commence par initaliser les registres rax, et rcx (counter) puis on compare rcx à 5 avec JGE (plus grand ou égal) si c'est le cas on quitte, sinon on commence le calcul
 et on incrémente de 1 avec inc le counter et on fais un jmp pour répeter la bloc d'instruction.



### CheatSheet général sur le nasm :

![image](https://user-images.githubusercontent.com/75935486/152057885-07742345-bef3-4793-85da-f631fe8101d5.png)
