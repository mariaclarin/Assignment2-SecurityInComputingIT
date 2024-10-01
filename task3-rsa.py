# SOME FUNCTIONALITY OF THIS CODE IS DERIVED FROM EXAMPLE CODE OF LECTORIAL 6
# Functions Referenced: generate_keys(), encrypt_file(), decrypt_file(), sign_data(), and verify_signature()
# File Reference: /L6-code/rsa_with_signature.py
# Written and Published by Shekhar Kalra on Canvas

# Importing necessary libraries (Cryptography, time and OS)
import os
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding


#BASE fix to allow compatibility on all operating systems 
BASE = os.path.dirname(os.path.abspath(__file__))

# KEY GENERATION ------
# this function generates the private key and derives the public key from it
def generate_keys(key_size_input=1024): # 1024 as defaul parameter but changeable if another value is passed
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size_input,
    )
    public_key = private_key.public_key()

    return private_key, public_key

# KEY OUTPUT HANDLING -------
# this function saves the private and public key as byte format and decoded format
def save_keys(private_key, public_key, private_key_path, public_key_path):
    # pem format to store in the saved key files in keys
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    #save the private key and public key in seperate files 
    with open(private_key_path, "wb") as priv:
        priv.write(private_key_pem)
        
    with open(public_key_path, "wb") as pub:
        pub.write(public_key_pem)

# ENCRYPTION ----
# this function produces an encrypted file from a plaintext file input.
def encrypt_file(input_file_path, public_key, encrypted_output_path):
    # opening and reading the input plaintext file
    with open(input_file_path, "rb") as file:
        plaintext = file.read()

    # encryption process, with additional OAEP padding
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # creating an output file that the ciphertext is written in
    with open(encrypted_output_path, "wb") as file:
        file.write(ciphertext)

    return ciphertext, input_file_path, encrypted_output_path


# DECRYPTION ------
# this function reverses the process of encryption
def decrypt_file(encrypted_file_path, private_key, decrypted_output_path):
    # opening and reading the input ciphertext file
    with open(encrypted_file_path, "rb") as file:
        ciphertext = file.read()

    # decryption process, with additional OAEP padding
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # saving the plaintext as an output file
    with open(decrypted_output_path, "wb") as file:
        file.write(plaintext)

    return plaintext, decrypted_output_path


# SIGNING DATA -------
# this function signs the data/creates the signature with the private key
def sign_data(data, private_key):
    signature = private_key.sign(
        data,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# VERIFYING SIGNATURES -------
# this function verifies the signature with the public key
def verify_signature(data, signature, public_key):
    try:
        public_key.verify(
            signature,
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Signature verification failed: {e}") 
        return False

# TIME MEASUREMENT ------
# this function measures the time for a function call that is passed as its parameter
def measure_time(operation, *args):
    start_time = time.time()
    result = operation(*args) # operation is the function, *args is any required parameters of that operation
    end_time = time.time()
    elapsed_time = end_time - start_time
    return elapsed_time, result  # return the total elapsed time of the function

# MAIN FUNCTION ------
# this function calls all the functions and format output results
def main():
    # For loop to run for two specified key sizes 1024 and 2048-bits
    for key_size in [1024, 2048]:
        # saving the private & public keys for each key size iteration
        if key_size == 1024:
            private_key_path = os.path.join(BASE, "keys", "task3_1024bit_privatekey")
            public_key_path = os.path.join(BASE,  "keys", "task3_1024bit_publickey")
        elif key_size == 2048:
            private_key_path = os.path.join(BASE, "keys", "task3_2048bit_privatekey")
            public_key_path = os.path.join(BASE,  "keys", "task3_2048bit_publickey")
        else:
            print("Key size ", key_size, " not included in the option.")

        # Generates private & public keys
        private_key, public_key = generate_keys(key_size)

        # Save the keys to the seperate paths and print  
        save_keys(private_key, public_key, private_key_path, public_key_path)

        # Declare file paths
        input_file_path = os.path.join(BASE, "input", "task3.txt")
        encrypted_file_path = os.path.join(BASE, "output", "task3_encrypted")
        decrypted_file_path = os.path.join(BASE,  "output", "task3_decrypted")

        # # Print formatting and title for Encryption
        # print('\n'+ '=' *40, "\n            ENCRYPTION RSA", "\n"+"="*40)

        # Function call to encrypt input file, save the output file, and measure the time
        encrypt_time, (ciphertext, input_file_path, encrypted_output_path) = measure_time(
            encrypt_file, input_file_path, public_key, encrypted_file_path
        )

        # Function call to decrypt encrypted file, save the output file, and measure the time
        decrypt_time, (plaintext, decrypted_output_path) = measure_time(
            decrypt_file, encrypted_file_path, private_key, decrypted_file_path
        )
        
        # Saving the elapsed encryption-decryption time for each key size function call
        if key_size == 1024:
            encrypt_1024_time = encrypt_time
            decrypt_1024_time = decrypt_time
        elif key_size == 2048:
            encrypt_2048_time = encrypt_time
            decrypt_2048_time = decrypt_time
        else:
            print("Key size ", key_size, " not included in the option.")

        # Signing the original data
        with open(input_file_path, "rb") as file:
            original_data = file.read()
        signature = sign_data(original_data, private_key)

        verification_status = verify_signature(original_data, signature, public_key)

    
    # Print formatting and title for Signature
    print('\n'+ '=' *40, "\n              SIGNATURE", "\n"+"="*40)
    # Print the signature
    print("Signature:")
    print(signature.hex(), '\n')
    # Verify the signatures
    print("Signature Verification Status:", verification_status)

    # Print the time comparison for the 2 key sizes
    print('\n'+ '=' *40, "\n         TIME COMPARISON", "\n"+"="*40)
    print(f"Encryption time for 1024-bit key: {encrypt_1024_time:.6f} seconds")
    print(f"Decryption time for 1024-bit key: {decrypt_1024_time:.6f} seconds\n")
    
    print(f"Encryption time for 2048-bit key: {encrypt_2048_time:.6f} seconds")
    print(f"Decryption time for 2048-bit key: {decrypt_2048_time:.6f} seconds\n")



if __name__ == "__main__":
    main()



