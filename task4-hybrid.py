# SOME FUNCTIONALITY OF THIS CODE IS DERIVED FROM EXAMPLE CODE OF LECTORIAL 7
# Functions Referenced: encrypt_message(), decrypt_message(), generate_rsa_keys()
# File Referenced: /L7-code/hybridcrypto.py 
# Written and Published by Shekhar Kalra on Canvas

# importing necessary libraries (Cryptography and OS)
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import b64encode
from os import urandom
import os

# BASE fix to allow compatibility on all operating systems
BASE = os.path.dirname(os.path.abspath(__file__))

# generate RSA keys (Public and Private)
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# function to encrypt the message using hybrid encryption (AES + RSA)
def encrypt_message(plaintext, rsa_public_key):
    # generate a random symmetric key for AES (32 bytes for AES-256)
    aes_key = urandom(32)  # AES-256

    # encrypt the data with AES (symmetric encryption)
    iv = urandom(16)  # initialization vector
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext.encode()) + padder.finalize()
    encrypted_data = encryptor.update(padded_plaintext) + encryptor.finalize()

    # encrypt the AES symmetric key with RSA (asymmetric encryption)
    encrypted_aes_key = rsa_public_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return encrypted_data, iv, encrypted_aes_key

# function to decrypt the message using hybrid decryption (RSA + AES)
def decrypt_message(encrypted_data, iv, encrypted_aes_key, rsa_private_key):
    # decrypt the AES symmetric key using the private RSA key
    aes_key = rsa_private_key.decrypt(
        encrypted_aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # decrypt the message using the decrypted AES key (AES)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_message = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_message = unpadder.update(padded_message) + unpadder.finalize()

    return decrypted_message.decode()

# MAIN FUNCTION ----
# This function is responsible for reading the file, encrypting it, and displaying keys and outputs
def main():
    # generate RSA keys
    rsa_private_key, rsa_public_key = generate_rsa_keys()

    # save RSA keys to files
    rsa_private_key_path = os.path.join(BASE, 'keys', 'task4_rsa_private_key')
    rsa_public_key_path = os.path.join(BASE, 'keys', 'task4_rsa_public_key')

    # save the private RSA key
    with open(rsa_private_key_path, 'wb') as private_file:
        private_file.write(
            rsa_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # save the public RSA key
    with open(rsa_public_key_path, 'wb') as public_file:
        public_file.write(
            rsa_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    # load the plaintext message from task1.txt
    with open(os.path.join(BASE, 'input', 'task1.txt'), 'r') as f:
        plaintext_message = f.read()

    # encrypt the message
    encrypted_data, iv, encrypted_aes_key = encrypt_message(plaintext_message, rsa_public_key)

    # print encrypted outputs
    print('\n' + '=' * 40, "\n        ENCRYPTION PROCESS", "\n" + '=' * 40)
    print("\nEncrypted Data (Message):", b64encode(encrypted_data).decode())
    print("\nInitialization Vector (IV):", b64encode(iv).decode())
    print("\nEncrypted AES Symmetric Key:", b64encode(encrypted_aes_key).decode())

    # save the encrypted data and key to files
    encrypted_data_path = os.path.join(BASE, 'output', 'task4_encrypted')
    encrypted_aes_key_path = os.path.join(BASE, 'keys', 'task4_encrypted_aes_key')
    iv_path = os.path.join(BASE, 'keys', 'task4_iv')

    with open(encrypted_data_path, 'wb') as enc_data_file:
        enc_data_file.write(encrypted_data)

    with open(encrypted_aes_key_path, 'wb') as enc_key_file:
        enc_key_file.write(encrypted_aes_key)

    with open(iv_path, 'wb') as iv_file:
        iv_file.write(iv)

    # decrypt the message
    decrypted_message = decrypt_message(encrypted_data, iv, encrypted_aes_key, rsa_private_key)

    # print formatting and title for the Decryption process
    print('\n' + '=' * 40, "\n        DECRYPTION PROCESS", "\n" + '=' * 40)
    print("Decrypted Message:", decrypted_message)

    # save the decrypted message to a file
    decrypted_message_path = os.path.join(BASE, 'output', 'task4_decrypted')
    with open(decrypted_message_path, 'w') as dec_msg_file:
        dec_msg_file.write(decrypted_message)

if __name__ == "__main__":
    main()
