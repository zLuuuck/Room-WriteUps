# 🧠 TryHackMe – W1seGuy (Cryptography CTF)

## Descrição da Sala  
W1seGuy é um desafio de criptografia que explora uma cifragem XOR básica com chave repetida de 5 caracteres.  
O objetivo é recuperar duas flags:

- **Flag 1**: cifrada via XOR e apresentada em hexadecimal.  
- **Flag 2**: revelada após o envio da chave correta ao servidor.

---

## ⚙️ Funcionamento do Desafio

O servidor:

- Gera uma **chave aleatória de 5 caracteres** (letras e dígitos).
- Aplica **XOR entre a flag e a chave repetida**.
- Converte o resultado para **hexadecimal** e o envia ao cliente.
- Espera que o cliente envie a chave correta para revelar a segunda flag.

---

## 🧩 Lógica de Resolução

### 1. Ataque de Known-Plaintext
Sabendo que flags no TryHackMe seguem o padrão `THM{...}`:

- Aplicamos XOR entre os 4 primeiros bytes do texto cifrado e `THM{` para descobrir os 4 primeiros caracteres da chave.

### 2. Força Bruta no Caractere Restante

- Como a chave tem 5 caracteres, realizamos brute-force nos **62 possíveis caracteres alfanuméricos (A-Za-z0-9)** para o último byte da chave.

### 3. Descriptografar e Validar

- Com a chave completa, aplicamos XOR novamente sobre o texto inteiro.
- Se o resultado for legível e terminar com `}`, a flag foi recuperada com sucesso.

---

## 🛠️ Ferramentas e Estratégias

- Python 3  
- XOR com chave repetida  
- Ataque de texto conhecido (known-plaintext)  
- Brute-force parcial  
- Validação de padrão (`THM{}`)
- VSCode para criação do script
- NC(Netcat) para conexão do servidor

---

## 💡 Script de Automação (Python)

```python
import string
from itertools import product

def xor_descriptografar(texto_cifrado_hex, texto_claro_conhecido="THM{", tamanho_chave=5):
    bytes_texto_cifrado = bytes.fromhex(texto_cifrado_hex)
    bytes_texto_claro_conhecido = texto_claro_conhecido.encode()

    # Descobrir os primeiros bytes da chave usando a parte conhecida do texto claro
    bytes_chave = [bytes_texto_cifrado[i] ^ bytes_texto_claro_conhecido[i] for i in range(len(bytes_texto_claro_conhecido))]

    # Espaço reservado para os bytes restantes da chave
    for _ in range(len(bytes_texto_claro_conhecido), tamanho_chave):
        bytes_chave.append(0)

    conjunto_caracteres = string.ascii_letters + string.digits

    # Força bruta para os bytes restantes da chave
    for caracteres_combinados in product(conjunto_caracteres, repeat=tamanho_chave - len(bytes_texto_claro_conhecido)):
        for i, char_atual in enumerate(caracteres_combinados):
            bytes_chave[len(bytes_texto_claro_conhecido) + i] = ord(char_atual)

        chave = bytes(bytes_chave)
        descriptografado = bytes([bytes_texto_cifrado[i] ^ chave[i % tamanho_chave] for i in range(len(bytes_texto_cifrado))])

        try:
            decodificado = descriptografado.decode()
            if decodificado.startswith("THM{") and decodificado.endswith("}"):
                return decodificado, chave.decode()
        except UnicodeDecodeError:
            continue

    return None, None

if __name__ == "__main__":
    texto_cifrado_hex = input("Cole o XOR codificado (hex): ").strip()
    flag_encontrada, chave_descoberta = xor_descriptografar(texto_cifrado_hex)

    if flag_encontrada:
        print("\n[+] Flag encontrada:", flag_encontrada)
        print("[+] Chave descoberta:", chave_descoberta)
    else:
        print("[-] Não foi possível descriptografar a flag.")
```
---
## 🧠 Lições Aprendidas

### ✅ Conceituais

- Criptografia fraca com XOR e chave curta é altamente vulnerável, principalmente se a estrutura do plaintext for previsível.
- Conhecimento prévio de padrões como `THM{...}` viabiliza ataques de known-plaintext extremamente eficazes.
- A repetição da chave em cifragem simétrica (key-reuse) permite ataques segmentados que reduzem significativamente o espaço de busca.

### 🧪 Técnicas

- Utilizar XOR reverso permite identificar a chave byte a byte com base em fragmentos conhecidos.
- Ataques de força bruta são viáveis quando:
  - O comprimento da chave é pequeno.
  - O conjunto de caracteres possível é limitado (ex: letras e números).
- Validação de prefixo e sufixo (`startswith`, `endswith`) é útil para verificar rapidamente se o resultado da decodificação é válido.

### 🚩 Boas Práticas

- Sistemas reais nunca devem usar XOR puro com chave fixa ou pequena.
- Sempre utilize criptografia autenticada (ex: AES-GCM, ChaCha20-Poly1305) com geração segura de chaves.
- Mesmo desafios simples como este ajudam a compreender os princípios de quebra de criptografia na prática.

---

## 🖼️ Execução

Abaixo está uma captura de tela da execução do script de descriptografia:

![Execução do Script](caminho/para/sua/imagem.png)

> 📌 Substitua `caminho/para/sua/imagem.png` pelo caminho real da sua imagem.  
> Exemplo: `images/execution.png` ou o link direto de um GitHub CDN.
