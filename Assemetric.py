import os
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes, padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class HybridEncryptionSystem:
    def __init__(self, rsa_key_size: int = 2048, aes_key_size: int = 32):
        self.rsa_key_size = rsa_key_size
        self.aes_key_size = aes_key_size
        self._generate_rsa_keys()

    def _generate_rsa_keys(self):
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.rsa_key_size,
            backend=default_backend()
        )
        self._public_key = self._private_key.public_key()

    def export_public_key(self) -> bytes:
        public_pem = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return public_pem

    def export_private_key(self, password: bytes = None) -> bytes:
        pem = self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        return pem

    def hybrid_encrypt(self, plaintext: bytes, public_key_pem: bytes = None) -> dict:
        if public_key_pem:
            public_key = serialization.load_pem_public_key(
                public_key_pem,
                backend=default_backend()
            )
        else:
            public_key = self._public_key

        sym_key = os.urandom(self.aes_key_size)
        iv = os.urandom(16)

        padder = sym_padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext)
        padded_data += padder.finalize()

        cipher = Cipher(
            algorithms.AES(sym_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data)
        ciphertext += encryptor.finalize()

        enc_sym_key = public_key.encrypt(
            sym_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return {
            'ciphertext': ciphertext,
            'iv': iv,
            'enc_sym_key': enc_sym_key
        }

    def hybrid_decrypt(self, enc_dict: dict, private_key_pem: bytes = None, password: bytes = None) -> bytes:
        if private_key_pem:
            private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=password,
                backend=default_backend()
            )
        else:
            private_key = self._private_key

        encrypted_key = enc_dict['enc_sym_key']
        decrypted_sym_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        cipher = Cipher(
            algorithms.AES(decrypted_sym_key),
            modes.CBC(enc_dict['iv']),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_plain = decryptor.update(enc_dict['ciphertext'])
        padded_plain += decryptor.finalize()

        unpadder = sym_padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plain)
        plaintext += unpadder.finalize()

        return plaintext

if __name__ == "__main__":
    system = HybridEncryptionSystem()

    public_key = system.export_public_key()
    private_key = system.export_private_key()

    with open('public_key.pem', 'wb') as pub_file:
        pub_file.write(public_key)

    with open('private_key.pem', 'wb') as priv_file:
        priv_file.write(private_key)

    choice = input("Выберите режим:\n1 - Шифровать\n2 - Расшифровать\n> ")

    if choice == '1':
        text = input("Введите слово для шифрования: ")
        plaintext_bytes = text.encode('utf-8')

        enc_result = system.hybrid_encrypt(plaintext_bytes)

        ciphertext_b64 = base64.b64encode(enc_result['ciphertext']).decode('utf-8')
        iv_b64 = base64.b64encode(enc_result['iv']).decode('utf-8')
        key_b64 = base64.b64encode(enc_result['enc_sym_key']).decode('utf-8')

        print("\n--- Результаты шифрования ---")
        print(f"Ciphertext: {ciphertext_b64}")
        print(f"IV: {iv_b64}")
        print(f"Encrypted AES key: {key_b64}")

    elif choice == '2':
        ciphertext_b64 = input("Введите Ciphertext (Base64): ")
        iv_b64 = input("Введите IV (Base64): ")
        key_b64 = input("Введите Encrypted AES key (Base64): ")

        ciphertext = base64.b64decode(ciphertext_b64)
        iv = base64.b64decode(iv_b64)
        encrypted_key = base64.b64decode(key_b64)

        enc_data = {
            'ciphertext': ciphertext,
            'iv': iv,
            'enc_sym_key': encrypted_key
        }

        decrypted_bytes = system.hybrid_decrypt(
            enc_data,
            private_key_pem=None
        )
        decrypted_text = decrypted_bytes.decode('utf-8')

        print("\n--- Результат расшифровки ---")
        print(f"Расшифрованное слово: {decrypted_text}")

    else:
        print("Неверный выбор режима.")