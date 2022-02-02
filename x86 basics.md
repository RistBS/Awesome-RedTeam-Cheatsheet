


#### **1. Les registres :**

![image](https://user-images.githubusercontent.com/75935486/152057010-ffd64c4f-8fa1-4f5f-8d24-280548268268.png)

```asm
rax = 64 BITS | eax = 32 BITS | ax = 16 BITS | ah = 8 BITS (partie haute) | al (basse)
rdi = 64 BITS | edx = 32 BITS | bx = 16 BITS | bh = 8 BITS (partie haute) | bl (basse)
rsi = 64 BITS | ecx = 32 BITS | cx = 16 BITS | ch = 8 BITS (partie haute) | cl (basse) 
rdx = 64 BITS | ebx = 32 BITS | dx = 16 BITS | dh = 8 BITS (partie haute) | dl (basse)
```
exemple:
```asm
EAX: 12 34 56 78
AX: 56 78
AH: 56
AL: 78
```


##### 1.2 - les FLAGS :

les flags sont codé sur 1 bit

- CS : code flag
- DS : data flag
- SS : stack flag
- ES : extra flag


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

- JMP: jump vers une étiquette call : appelle les instructions d'une étiquette
- MOV: 'destination', 'source' (valeur dans regsitre)
- MOVZX/MOVSX: movzx permet la conversion des nombres naturels en plus grand format alors que movsx le fais pour des nombres entiers. 
- SYSCALL: appel système 
- RET: return 
- INC: incrémentation de 1 
- DEC: décrémentation de 1
- LOOP: équivalent à while, c'est une boucle. 
- LEA: Cette instruction permet d'incrémenter un registre ou un emplacement mémoire.
- NEG: Négation
- CMP: Comparaison

opération arithmétique:
- SUB : soustraction 
- ADD : addition 
- DIV/IDIV : division et division non signé 
- MUL/IMUL: imul effectue une multiplication signée alors que mul peux uniquement sur du non-signé soit entièrement Positive



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

#### **7. boucles:**

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

#### 8. la stack:

- POP : dépile dans la stack 
- PUSH : empile en haut de la stack
- PUSHA : empiler les 8 registres généraux sur la pile
- POPA : positionne les valeurs des 8 registres à partir des 8 valeurs au sommet de la pile

exemple :
```asm
mov rax, [rsp] ; RAX prend la première valeur au sommet de pile
mov rax, [rsp+2] ; RAX prend la deuxième valeur au sommet de pile
mov rax, [rsp+3] ; RAX prend la troisième valeur au sommet de pile
```


### CheatSheet général sur le nasm :

![image](https://user-images.githubusercontent.com/75935486/152057885-07742345-bef3-4793-85da-f631fe8101d5.png)
