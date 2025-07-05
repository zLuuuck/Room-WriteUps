# 🔐 XOR Flag Reverser – TryHackMe: W1seGuy

Este repositório contém a análise e o script Python utilizados para resolver o desafio de criptografia **W1seGuy** da plataforma TryHackMe.

---

## 📖 Visão geral do desafio

A máquina da sala **W1seGuy** roda um script Python que criptografa uma flag usando o algoritmo XOR com uma **chave de 5 caracteres**. O script fornece apenas a saída criptografada, em formato hexadecimal, e espera que o usuário descubra a **chave correta** para revelar a flag final.

Após um pouco de análise, vemos que nosso objetivo é obter:
- A **chave secreta** utilizada
- A **flag original** em texto claro

---

## 🧠 Entendendo o algoritmo da máquina

O código fornecido pela sala realiza as seguintes etapas:

1. Gera uma **chave aleatória** de 5 caracteres alfanuméricos.
2. Aplica a cifra **XOR** entre a flag (`flag.txt`) e essa chave, repetindo a chave ciclicamente.
3. Codifica o resultado em **hexadecimal**.
4. Envia a mensagem:

```
This XOR encoded text has flag 1: [xor encoded]
What is the encryption key? [input, requisitando a chave secreta]
```
## 🧮 Conceito de XOR aplicado

A operação XOR (`^`) tem uma propriedade fundamental:

A ^ B = C ⇒ C ^ B = A

Ou seja, se temos o resultado (`C`) e sabemos o operando (`B`), conseguimos recuperar o original (`A`).

Isso permite que, com um trecho conhecido do texto original (ex: `"THM{"`), possamos reverter a chave usada na cifra.

---
