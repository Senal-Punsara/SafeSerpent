import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import time

ALGORITHM = "AES"
KEY_SIZE = 32  # 256 bits
ITERATION_COUNT = 100000
TAG_LENGTH = 16  # 128 bits

def encrypt_file(file_path, password, encrypted_file_path):
    salt = os.urandom(16)
    key = derive_key_from_password(password, salt)

    with open(file_path, 'rb') as f:
        plaintext = f.read()

    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    with open(encrypted_file_path, 'wb') as f:
        f.write(base64.b64encode(ciphertext) + b'\n')
        f.write(base64.b64encode(nonce) + b'\n')
        f.write(base64.b64encode(salt) + b'\n')

def decrypt_file(encrypted_file_path, password, decrypted_file_path):
    with open(encrypted_file_path, 'rb') as f:
        ciphertext = base64.b64decode(f.readline().strip())
        nonce = base64.b64decode(f.readline().strip())
        salt = base64.b64decode(f.readline().strip())

    key = derive_key_from_password(password, salt)

    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    with open(decrypted_file_path, 'wb') as f:
        f.write(plaintext)

def derive_key_from_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATION_COUNT,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# if __name__ == "__main__":
#     password = "3cea76def039a224e90df5adb04339547be0254e9fe77b6df0bea9cbc1977a94"

#     #Encrypt the file
#     start_time = time.time()
#     encrypt_file("arduino_for_loop.h5", password, "arduino_for_loop.h5.enc")
#     end_time = time.time()
#     time_taken = end_time - start_time
#     print(f"Time taken to Encrypt the file: {time_taken} seconds")
#     print("The file has been encrypted.")

#     #Decrypt the file
#     start_time = time.time()
#     decrypt_file("arduino_for_loop.h5.enc", password, "arduino_for_loop.h5")
#     end_time = time.time()
#     time_taken = end_time - start_time
#     print(f"Time taken to decrypt the file: {time_taken} seconds")
#     print("The file has been decrypted.")