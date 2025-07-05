import string
from itertools import product

def xor_decrypt(ciphertext_hex, known_plaintext="THM{", key_length=5):
    ciphertext_bytes = bytes.fromhex(ciphertext_hex)
    known_bytes = known_plaintext.encode()

    # Descobrir os primeiros bytes da chave usando plaintext conhecido
    key_bytes = [ciphertext_bytes[i] ^ known_bytes[i] for i in range(len(known_bytes))]

    # Placeholder para os bytes restantes da chave
    for _ in range(len(known_bytes), key_length):
        key_bytes.append(0)

    charset = string.ascii_letters + string.digits

    # Brute-force para os bytes restantes da chave
    for chars in product(charset, repeat=key_length - len(known_bytes)):
        for i, c in enumerate(chars):
            key_bytes[len(known_bytes) + i] = ord(c)

        key = bytes(key_bytes)
        decrypted = bytes([ciphertext_bytes[i] ^ key[i % key_length] for i in range(len(ciphertext_bytes))])

        try:
            decoded = decrypted.decode()
            if decoded.startswith("THM{") and decoded.endswith("}"):
                return decoded, key.decode()
        except:
            continue

    return None, None

if __name__ == "__main__":
    ciphertext_hex = input("Cole o XOR encoded (hex): ").strip()
    flag, key = xor_decrypt(ciphertext_hex)

    if flag:
        print("\n[+] Flag encontrada:", flag)
        print("[+] Chave descoberta:", key)
    else:
        print("[-] Não foi possível descriptografar a flag.")
