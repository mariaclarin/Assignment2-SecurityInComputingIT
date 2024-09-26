# make sure you have installed cryptography library
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
import os
import os.path

# a fix for making paths working on all OS
BASE = os.path.dirname(os.path.abspath(__file__))


# function to encrypt a plain text file and produce encrypted file.
# a key derivation function (PBKDF) is used to derive a strong key from the password,
# using a salt for better security.
# https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/
def encrypt_file(input_file_path, output_file_path, password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode())
    

    # A random IV is generated for each encryption session to ensure that 
    # encryption of the same data results in different ciphertexts.
    # MODE = CBC
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    # open the plaintext file to be read bytewise
    # look at the mode= rb (read, byte)
    with open(input_file_path, 'rb') as f:
        plaintext = f.read()
    
     # AES operates on blocks of data, so PKCS7 padding is 
    # applied to ensure the plaintext is a multiple of the block size.
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

     # finally the encryption, Yay!
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # create the encrypted file, look at the mode= wb (write).
    # The salt, IV, and encrypted data are all written to the output file.
    with open(output_file_path, 'wb') as f:
        f.write(salt + iv + ciphertext)
    
    return salt, iv, ciphertext, key, input_file_path


# function to decypt the encrypted file
# just the reverse steps
def decrypt_file(input_file_path, output_file_path, password):
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
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    with open(output_file_path, 'wb') as f:
        f.write(plaintext)
    
    return plaintext, key

# call encryption function
#prints a line separator
print('\n'+ '=' *40, "\nENCRYPTION CBC", "\n"+"="*40)



# choose any random password for the third argument
salt, iv, ciphertext, key, input_file_path = encrypt_file(BASE + '/input/task1.txt', BASE + '/output/task1', 's4115243')
print("Successfully encrypted file ", input_file_path)
print("Salt: ", salt.hex())  # Print the salt in hexadecimal format
print("IV: ", iv.hex())  # Print the IV in hexadecimal format
print("\nCiphertext: ","\n"+ ciphertext.hex())  # Print the ciphertext in hexadecimal format
print("\nEncryption Key: ", key.hex())  # Print the key in hexadecimal format

print('─' * 10) 

# call decryption function 

# choose any random password for the third argument
decrypted_text, decryption_key = decrypt_file(BASE + '/output/task1', BASE + '/output/decrypted1', 's4115243')
print("Now look at the decrypted file inside out sub-directory")
print("Decrypted Text:")
print(decrypted_text.decode())  # Decode the bytes to a string
print("\nDecryption Key:")
print(decryption_key.hex())  # Print the key in hexadecimal format
print('─' * 10) 