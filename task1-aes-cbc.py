# SOME FUNCTIONALITY OF THIS CODE IS DERIVED FROM EXAMPLE CODE OF LECTORIAL 5
# Functions Referenced: encrypt_file() and decrypt_file()
# File Referenced: /L5-code/symmetric/aes_cbc_file.py 
# Written and Published by Shekhar Kalra on Canvas

# Importing necessary libraries (Cryptography and OS)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
import os
import os.path

#BASE fix to allow compatibility on all operating systems 
BASE = os.path.dirname(os.path.abspath(__file__))


# ENCRYPTION ----
# this function produces an encrypted file from a plaintext file input.
def encrypt_file(input_file_path, encrypted_output_path, password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(       
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode())
    

    # generates IV to ensure randomization of data results in different cyphertext
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv)) #using CBC mode
    encryptor = cipher.encryptor() #calls the encryptor

    # opening and reading the input plaintext file
    with open(input_file_path, 'rb') as f:
        plaintext = f.read()
    
    # adds padding to ensure consistent size of blocks to operate AES
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    # encryption process, finalized and saved as ciphertext variable
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # creating an output file that the salt, iv, and ciphertext is written in
    with open(encrypted_output_path, 'wb') as f:
        f.write(salt + iv + ciphertext)

    return ciphertext, key, input_file_path, encrypted_output_path


# DECRYPTION ------
# this function reverses the process of encryption
def decrypt_file(input_file_path, decrypted_output_path, password):
    
    # opening and reading the input ciphertext file
    with open(input_file_path, 'rb') as f:
        salt = f.read(16)
        iv = f.read(16)
        ciphertext = f.read()

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode())
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor() #calls the decryptor

    # decryption process, finalized and saved as variable
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # remove the padding from the plaintext
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    # saving the plaintext as an output file
    with open(decrypted_output_path, 'wb') as f:
        f.write(plaintext)
    
    return plaintext, key, decrypted_output_path


# MAIN FUNCTION ------
# this function calls all the functions and format output results
def main():
    # Declare file paths
    input_file_path = os.path.join(BASE, "input", "task1.txt")
    encrypted_file_path = os.path.join(BASE, "output", "task1_encrypted")
    decrypted_file_path = os.path.join(BASE,  "output", "task1_decrypted")
    # Print formatting and title for Encryption
    print('\n'+ '=' *40, "\n            ENCRYPTION CBC", "\n"+"="*40)


    # Function call to encrypt, save output file, using studentID for password
    ciphertext, encryption_key, input_file_path, encrypted_output_path = encrypt_file(input_file_path, encrypted_file_path, 's4115243')

    # Print results as output display
    print("Successfully encrypted plaintext file:") 
    print(input_file_path) # validate input file directory
    print("\nEncrypted ciphertext saved in: ")
    print(encrypted_output_path) # saved encrypted file directory

    print("\n1. ENCRYPTION KEY:")
    print(encryption_key.hex()) # .hex() is for hexadecimal format
    print("\n2. ENCRYPTED TEXT:")
    print(ciphertext.hex())


    # Print formatting and title for Decryption
    print('\n\n'+ '=' *40, "\n            DECRYPTION CBC", "\n"+"="*40)

    # Function call to decrypt, save output file, using studentID for password
    plaintext, decryption_key, decrypted_output_path = decrypt_file(encrypted_file_path, decrypted_file_path, 's4115243')

    # Print results as output display
    print("Successfully decrypted the file! Available in the directory:") 
    print(decrypted_output_path) # saved decrypted file directory

    print("\n1. DECRYPTION KEY:")
    print(decryption_key.hex())  
    print("\n2. DECRYPTED TEXT:")
    print(plaintext.decode(),  '\n')  # decode from bytes to string

if __name__ == "__main__":
    main()
