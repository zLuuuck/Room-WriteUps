# 🔐 XOR Flag Reverser – TryHackMe: W1seGuy

Este repositório contém a análise e o script Python utilizados para resolver o desafio de criptografia **W1seGuy** da plataforma TryHackMe.

---

## 📖 Visão geral do desafio

A máquina da sala **W1seGuy** roda um script Python que criptografa uma flag usando o algoritmo XOR com uma **chave de 5 caracteres**. O script fornece apenas a saída criptografada, em formato hexadecimal, e espera que o usuário descubra a **chave correta** para revelar a flag final.

O objetivo deste projeto é realizar o processo **inverso da criptografia** para descobrir:

- A **chave secreta** utilizada
- A **flag original** em texto claro

---

## 🧠 Entendendo o algoritmo da máquina

O código fornecido pela sala realiza as seguintes etapas:

1. Gera uma **chave aleatória** de 5 caracteres alfanuméricos.
2. Aplica a cifra **XOR** entre a flag (`flag.txt`) e essa chave, repetindo a chave ciclicamente.
3. Codifica o resultado em **hexadecimal**.
4. Envia a mensagem:

