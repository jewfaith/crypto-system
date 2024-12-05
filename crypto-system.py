import os
import hashlib
import uuid
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


class crypto:
    def __init__(self):
        self.backend = default_backend()
        self.device_signature = self.generate_device_signature()
        self.rsa_private_key = None
        self.rsa_public_key = None
        self.generate_asymmetric_keys()
        self.save_public_key()

    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def generate_device_signature(self):
        unique_data = str(uuid.getnode()) + os.getenv("COMPUTERNAME", "unknown") + str(os.getpid())
        return hashlib.sha512(unique_data.encode()).digest()

    def generate_asymmetric_keys(self):
        self.rsa_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=self.backend
        )
        self.rsa_public_key = self.rsa_private_key.public_key()
        print("\n[INFO] Key generated")

    def save_public_key(self):
        if not self.rsa_public_key:
            raise ValueError("Key missing")

        public_pem = self.rsa_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        filename = "public.pem"
        with open(filename, "wb") as key_file:
            key_file.write(public_pem)
        print(f"\n[INFO] Key saved")

    def encrypt_message(self, message):
        if not self.rsa_public_key:
            raise ValueError("Key missing")

        ciphertext = self.rsa_public_key.encrypt(
            message.encode(),
            OAEP(
                mgf=MGF1(algorithm=SHA256()),
                algorithm=SHA256(),
                label=None
            )
        )

        return ciphertext

    def save_encrypted_message(self, encrypted_message):
        filename = "encrypted.bin"
        with open(filename, "wb") as file:
            file.write(encrypted_message)
        print(f"\n[INFO] Encrypted saved")

    def decrypt_message(self, encrypted_file_path):
        if not self.rsa_private_key:
            raise ValueError("Key absent")

        with open(encrypted_file_path, "rb") as file:
            ciphertext = file.read()

        plaintext = self.rsa_private_key.decrypt(
            ciphertext,
            OAEP(
                mgf=MGF1(algorithm=SHA256()),
                algorithm=SHA256(),
                label=None
            )
        )

        print(f"\n[INFO] Decrypted message: {plaintext.decode()}")
        return plaintext.decode()

    def self_destruct(self):
        self.rsa_private_key = None
        self.rsa_public_key = None
        self.device_signature = None

        print("")
        for file in ["public.pem", "encrypted.bin"]:
            if os.path.exists(file):
                os.remove(file)
                print(f"[INFO] {os.path.splitext(os.path.basename(file))[0].capitalize()} erased")

        os._exit(1)

    def run(self):
        while True:
            self.clear_screen()
            print("==== crypto-system ====")
            print("1. Encrypt message")
            print("2. Decrypt message")
            print("3. Destroy info")
            choice = input("Choose option: ")

            if choice == "1":
                message = input("\nEncrypt message: ")
                try:
                    encrypted = self.encrypt_message(message)
                    self.save_encrypted_message(encrypted)
                except Exception:
                    print("\n[ERROR] Error encrypting")
                input("[INFO] Return menu")

            elif choice == "2":
                encrypted_file_path = "encrypted.bin"
                try:
                    self.decrypt_message(encrypted_file_path)
                except Exception:
                    print("\n[ERROR] Error decrypting")
                input("[INFO] Return menu")

            elif choice == "3":
                self.self_destruct()

            else:
                print("\n[ERROR] Invalid option")
                input("[INFO] Return menu")


if __name__ == "__main__":
    crypto().run()
