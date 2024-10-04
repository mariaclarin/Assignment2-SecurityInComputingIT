"""
SOME FUNCTIONALITY OF THIS CODE IS BASED ON THE CONCEPTS EXPLAINED IN LECTORIAL 2 
- Concepts Referenced: RSA Cryptosystem (Encryption, Decryption, & Key generation)
- File Referenced: L2-EncryptionConcept.pdf
- Written and Published by Shekhar Kalra on Canvas

SOME FUNCTIONALITY OF THIS CODE IS ALSO DERIVED FROM EXTERNAL DOCUMENTATIONS AND AI TOOLS 
References:
ChatGPT (2024) Code explanations and suggestions for RSA prime number generation, bits conversion for integer digits, and PKCS#1 padding, OpenAI, accessed 29 September 2024.
    https://chat.openai.com/ 
Faulst (2018) Why PS does differ between PKCS1 v1.5 padding for signature and for encryption?, Cryptography Stack Exchange, accessed 2 October 2024
    https://crypto.stackexchange.com/questions/61178/why-ps-does-differ-between-pkcs1-v1-5-padding-for-signature-and-for-encryption
GeeksforGeeks (2015) Modular multiplicative inverse, GeeksforGeeks, accessed 29 September 2024
    https://www.geeksforgeeks.org/multiplicative-inverse-under-modulo-m/
GeeksforGeeks (2015) Primality Test | Set 3 (Miller-Rabin), GeeksforGeeks, accessed 29 September 2024.
    https://www.geeksforgeeks.org/primality-test-set-3-miller-rabin/
IBM Documentation (2023) PKCS #1 formats, IBM Corporation, accessed 2 October 2024
    https://www.ibm.com/docs/en/zos/2.5.0?topic=cryptography-pkcs-1-formats 
User545424 (2012) Code for Greatest Common Divisor in Python [closed], StackOverflow, accessed 29 September 2024
    https://stackoverflow.com/questions/11175131/code-for-greatest-common-divisor-in-python

"""
# Importing necessary libraries (os and random)
import random
import os

#BASE fix to allow compatibility on all operating systems 
BASE = os.path.dirname(os.path.abspath(__file__))

# function to calculate the greatest common divisor between 2 values
# Ref: https://stackoverflow.com/questions/11175131/code-for-greatest-common-divisor-in-python
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


# function to calculate the inverse mod with Extended Euclidean Algorithm
# Ref: https://www.geeksforgeeks.org/multiplicative-inverse-under-modulo-m/
def mod_inverse_euclidean(e, totient):
    #recursive function of the Extended Euclidean to get the gcd between 2 ints
    def extended_gcd(a, b): 
        if b == 0:          #base condition to break from recursion
            return a, 1, 0  
        gcd, x1, y1 = extended_gcd(b, a % b) #recursive call
        x = y1                 # x represents d (Private key) in finding e × d =1 mod (r) 
        y = x1 - (a // b) * y1 # y is Extended Euclidean theorem helper value (ax+by = gcd(a, b))
        return gcd, x, y 

    gcd, x, y = extended_gcd(e, totient)
    return x % totient


# function of square and multiply algorithm for modular exponentiation
# Ref: https://blog.xojo.com/2022/05/16/square-multiply-algorithm/
def modular_exponentiation(base, exponent, modulus):
    result = 1
    base = base % modulus 
    while exponent > 0: 
        if exponent % 2 == 1: #odd exponent check (only calculates for binary 1, 0 triggers right shift)
            result = (result * base) % modulus #multiply result and base
        exponent = exponent >> 1 #right shift exponent bit by bit
        base = (base * base) % modulus #square the base
    return result


# function for the Miller-Rabin Primality Test (validating prime numbers)
# https://www.geeksforgeeks.org/primality-test-set-3-miller-rabin/
def miller_rabin(n, k=40):  # k = number of rounds (higher = better accuracy)
    if n == 2 or n == 3: #MRPT works on nums higher than 3, so validate the primes below it
        return True
    if n <= 1 or n % 2 == 0: #negative or even values = not prime
        return False

    #calculate d and r such that d*2r = n-1
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    #looping through k rounds of the primality test
    for round in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for round in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

# function for random prime number generation 
def generate_prime(bits=34): #34 bits for 10-11 digit values (around 2^33 to 2^34)
    while True:
        num = random.getrandbits(bits)
        num |= (1 << bits - 1) | 1 #left shift and modify so the last bit are odd (ensuring prime)
        if miller_rabin(num): #validate the prime with MRPT
            return num


# KEY GENERATION ------
# this function follows the RSA calculation to generate private-public keys and saves the outputs
def generate_keys(private_key_path, public_key_path, bits=34):
    print('-'*50)

    print("STEP 1: Generate random large prime numbers p & q")
    p = generate_prime(bits) #randomly select large prime numbers p & q
    q = generate_prime(bits)

    print(f"p = {p}",f"\nq = {q}", '\n')
    print('-'*50)

    # calculate n = p * q
    n = p * q
    print(f"STEP 2: Calculate n = p * q ")
    print(f'= {p} * {q}')
    print(f'= {n}', '\n')

    # calculate φ(n) = (p-1)*(q-1)
    totient = (p - 1) * (q - 1)
    print('-'*50)
    print(f"STEP 3: Calculate φ(n) = (p-1) * (q-1) ")
    print(f'= ({p-1}) * ({q-1})')
    print(f'= {totient}', '\n')

    # pick an integer e where 1 < e < φ(n) and gcd(e, φ(n)) = 1
    e = random.randrange(2, totient)
    while gcd(e, totient) != 1:
        e = random.randrange(2, totient)
    print('-'*50)
    print(f"STEP 4: Choose an e such that 1 < e < φ(n) and gcd(e, φ(n)) = 1")
    print(f"e = {e}", '\n')
    
    # calculate d where d is the modular inverse of e mod φ(n)
    d = mod_inverse_euclidean(e, totient)
    print('-'*50)
    print(f"STEP 5: Calculate d such that d * e ≡ 1 mod φ(n).")
    print(f"d = {d}")
    print(f'(modular inverse of {e} mod {totient})', '\n')

    # save generated keys to the output files
    with open(public_key_path, "w") as pub:
        pub.write(f"Public Key (e) = {e}")
    with open(private_key_path, "w") as priv:
        priv.write(f"Private Key (d) = {d}")

    return (n, e), (n, d)


# PADDING -----
# function to add padding to an input message (following PKCS#1 v1.5)
'''
    For padding, just for example implementation, we follow PKCS#1 v1.5 format of: 0x00 | 0x02 | random non-zero bytes | 0x00 | message 
    Ref:
    https://crypto.stackexchange.com/questions/61178/why-ps-does-differ-between-pkcs1-v1-5-padding-for-signature-and-for-encryption
    https://www.ibm.com/docs/en/zos/2.5.0?topic=cryptography-pkcs-1-formats
'''
def padder(message, block_size):
    message_bytes = message.to_bytes((message.bit_length() + 7) // 8, byteorder='big') #converting the message to bytes and order it by byte-significance

    # calculating the required length of the padding to ensure consistent block size 
    # the -3 accounts for the 3 added padding bytes 0x00, 0x02, 0x00
    padding_length = block_size - len(message_bytes) - 3 
    
    # generate random non-zero bytes as the padding value with the length of the calculated padding length, joined into a single byte string
    padding = b''.join(random.choice(range(1, 256)).to_bytes(1, byteorder='big') for i in range(padding_length))
    
    # joining the sections into a padded message following the PKCS#1 v1.5 format: 0x00 | 0x02 | random non-zero bytes | 0x00 | message 
    padded_message = b'\x00\x02' + padding + b'\x00' + message_bytes
    print(f"\nPadded Message (in hex, PKCS#1 v1.5) : {padded_message.hex()}")
    print(f"Padded Message (in int) : {int.from_bytes(padded_message, byteorder='big')}\n")
    
    return int.from_bytes(padded_message, byteorder='big') #return as int data type to allow the mathematical calculations 


# function to remove padding from a padded message 
def unpadder(padded_message):
    padded_message_bytes = padded_message.to_bytes((padded_message.bit_length() + 7) // 8, byteorder='big') #converting the message to bytes and order it by byte-significance

    # find the 2nd occurence of the 0x00 seperator to identify the end of the padding and the start of the message
    seperator_index = padded_message_bytes.find(b'\x00', 2)
    
    # retrieving the unpadded message that is everything after the 2nd 0x00 seperator
    # PKCS#1 form: 0x00 | 0x02 | random non-zero bytes | 0x00 | message 
    message_bytes = padded_message_bytes[seperator_index + 1:]
    return int.from_bytes(message_bytes, byteorder='big') #return as int to allow the mathematical calculations


# ENCRYPTION ----
# function to encrypt the message (with padding)
def encrypt_message(message, public_key, encrypted_file_path):
    n, e = public_key
    print('-'*50)
    print(f"STEP 6: Encrypting message M = {message}")
    
    # call for padder() to add padding
    padded_message = padder(message, (n.bit_length() + 7) // 8)
    
    # RSA encryption calculation process
    ciphertext = modular_exponentiation(padded_message, e, n)
    print("C = M^e mod n ")
    print(f"  = {padded_message}^{e} mod {n}")
    print(f"  = {ciphertext}", "\n")

    # save the encrypted ciphertext to the specified path
    with open(encrypted_file_path, "w") as f:
        f.write(str(ciphertext))

    return ciphertext


# DECRYPTION ----
# function to decrypt the ciphertext and remove padding
def decrypt_message(ciphertext, private_key, decrypted_file_path):
    n, d = private_key
    print('-'*50)
    print(f"STEP 7: Decrypting ciphertext C = {ciphertext}")
    
    # RSA decryption calculation
    padded_message = modular_exponentiation(ciphertext, d, n)
    
    # call for unpadder() to remove the padding
    decrypted_message = unpadder(padded_message)
    
    # save the decrypted message to a file 
    with open(decrypted_file_path, "w") as f:
        f.write(str(decrypted_message))

    print("\nM = C^d mod n  (still includes padding)")
    print(f"  = {ciphertext}^{d} mod {n} ")
    print(f"  = {padded_message}")
    print(f"\nUnpadded Message: = {decrypted_message}", "\n")
    
    return decrypted_message


# MAIN FUNCTION ------
# this function calls all the functions and format output results
def main():
    print('\n'+ '=' *50, "\n           RSA ENCRYPTION-DECRYPTION", "\n"+"="*50, "\n")
    # Takes the user input for the message they want to encrypt

    while True:
        user_input = input("Enter message to encrypt (1-10 digit integer) : ")
        
        # Validate that the input is a 10-digit integer
        if user_input.isdigit() and len(user_input) <= 10:
            message = int(user_input)  # Convert the input to an integer
            break
        else:
            print("Invalid input! Please enter a valid 10-digit integer.\n")
    
    # Declare file paths
    private_key_path = os.path.join(BASE, "keys", "task5_manualRSA_privatekey.txt")
    public_key_path = os.path.join(BASE, "keys", "task5_manualRSA_publickey.txt")
    encrypted_file_path = os.path.join(BASE, "output", "task5_encrypted")
    decrypted_file_path = os.path.join(BASE,  "output", "task5_decrypted")

    # Generates private & public keys
    public_key, private_key = generate_keys(private_key_path, public_key_path, bits=34)
    
    # Encryption process of the message
    ciphertext = encrypt_message(message, public_key, encrypted_file_path)
    
    # Decryption process of the message
    decrypted_message = decrypt_message(ciphertext, private_key, decrypted_file_path)
    print('='*50)
    print(f"Decrypted message: {decrypted_message}")
    print('='*50, '\n')

if __name__ == "__main__":
    main()
