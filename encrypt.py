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
        f.write(base64.b64encode(ciphertext))
        f.write(b':')
        f.write(base64.b64encode(nonce))
        f.write(b':')
        f.write(base64.b64encode(salt))

def decrypt_file(encrypted_file_path, password, decrypted_file_path):
    with open(encrypted_file_path, 'rb') as f:
        parts = f.read().split(b':')

    ciphertext = base64.b64decode(parts[0])
    nonce = base64.b64decode(parts[1])
    # print(len(nonce))
    salt = base64.b64decode(parts[2])

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
#     password = "base64:5LeZYdrAfqPDyXBTh5pvmffkZG3m+wvfjbMKgLgQRHc="

# #     # Encrypt the file
# #     # encrypt_file("decryptClientFile/image.jpg", password, "decryptClientFile/image.jpg.enc")
# #     # print("The file has been encrypted.")

# #     # Decrypt the file
# #     # decrypt_file("decryptClientFile/image.jpg.enc", password, "decryptClientFile/image1.jpg")
# #     # print("The file has been decrypted.")


#     #Encrypt the file
#     start_time = time.time()
#     encrypt_file("decryptClientFile/file3_1.cfile", password, "decryptClientFile/file3_1.cfile.enc")
#     end_time = time.time()
#     time_taken = end_time - start_time
#     print(f"Time taken to Encrypt the file: {time_taken} seconds")
#     print("The file has been encrypted.")

#     #Decrypt the file
#     start_time = time.time()
#     decrypt_file("decryptClientFile/file3_1.cfile.enc", password, "decryptClientFile/file3_1.cfile")
#     end_time = time.time()
#     time_taken = end_time - start_time
#     print(f"Time taken to decrypt the file: {time_taken} seconds")
#     print("The file has been decrypted.")