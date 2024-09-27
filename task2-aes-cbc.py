# SOME FUNCTIONALITY OF THIS CODE IS DERIVED FROM EXAMPLE CODE OF LECTORIAL 5
# Functions Referenced: decrypt_file()
# File Referenced: /L5-code/symmetric/aes_cbc_file.py 
# Written and Published by Shekhar Kalra on Canvas

# importing necessary libraries (Cryptography and OS)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import binascii
import os

#BASE fix to allow compatibility on all operating systems 
BASE = os.path.dirname(os.path.abspath(__file__))

# DECRYPTION ----
# this function performs the decryption of AES-CBC encrypted ciphertext
def decrypt_aes_cbc(encrypted_hex_data, aes_key_hex, decrypted_output_path):
    
    # convert the hex-encoded key and ciphertext to bytes
    aes_key = binascii.unhexlify(aes_key_hex)
    encrypted_data = binascii.unhexlify(encrypted_hex_data)
    
    # extract the Initialization Vector (IV) from the first 16 bytes of the ciphertext
    iv = encrypted_data[:16]
    encrypted_data = encrypted_data[16:]

    # create a Cipher object using AES in CBC mode with the provided key and IV
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()  # initialize the decryptor object

    # decrypt the ciphertext and obtain the padded plaintext
    padded_plaintext = decryptor.update(encrypted_data) + decryptor.finalize()

    # remove PKCS7 padding from the plaintext
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    # write the decrypted plaintext to the specified output file
    with open(decrypted_output_path, 'wb') as f:
        f.write(plaintext)

    # return the plaintext as a string (for display purposes)
    return plaintext.decode('utf-8')


# MAIN FUNCTION ----
# This function is responsible for calling the decryption function and managing file paths.
# It also prints the decrypted plaintext and saves it in a separate output file.
def main():
    
    # CBC key and ciphertext as provided in task2.txt (hex-encoded)
    aes_key_hex = '140b41b22a29beb4061bda66b6747e14'
    encrypted_hex_data = ('4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee'
                          '2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81')
    
    # define the output file path using BASE to ensure compatibility across operating systems
    decrypted_output_path = os.path.join(BASE, 'output', 'task2_decrypted')

    # print formatting and title for the Decryption process
    print('\n' + '=' * 40, "\n            DECRYPTION CBC", "\n" + '=' * 40)

    # call the decryption function and get the decrypted plaintext
    decrypted_text = decrypt_aes_cbc(encrypted_hex_data, aes_key_hex, decrypted_output_path)

    # display the decrypted plaintext to the user
    print("\nSuccessfully decrypted the ciphertext!")
    print("\nDecrypted text:\n")
    print(decrypted_text)

    # confirm that the output file has been created
    print(f"\nDecrypted output has been saved to: {decrypted_output_path}")


# the main() function is called to execute the decryption process
if __name__ == "__main__":
    main()
