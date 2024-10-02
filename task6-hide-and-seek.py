"""

SOME FUNCTIONALITY OF THIS CODE IS DERIVED FROM EXAMPLE CODE OF LECTORIAL 7 
- Functions Referenced: encrypt_message(), decrypt_message()
- File Referenced: /L7-code/hybrid_crypto.py 
- Written and Published by Shekhar Kalra on Canvas

SOME FUNCTIONALITY OF THIS CODE IS ALSO DERIVED FROM EXTERNAL DOCUMENTATIONS AND AI TOOLS 
References:
User35396977 (2016) LSB-DCT based Image steganography, StackOverflow, accessed 29 Sept 2024.
    https://stackoverflow.com/questions/35396977/lsb-dct-based-image-steganography
User29677726 (2015) Steganography in lossy compression (JAVA), StackOverflow, accessed 29 Sept 2024.
    https://stackoverflow.com/questions/29677726/steganography-in-lossy-compression-java
ChatGPT (2024) Code explanations and suggestions for DCT-based steganography, OpenAI, accessed 29 Sept 2024.
    https://chat.openai.com/

"""

import numpy as np
from PIL import Image
import cv2  # OpenCV for working with DCT and inverse DCT
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from os import urandom
from base64 import b64encode, b64decode

# use BASE to get the file paths in a way that works on any operating system
BASE = os.path.dirname(os.path.abspath(__file__))

# AES encryption function
def aes_encrypt_message(plaintext, key):
    iv = urandom(16)  # generate a random 16-byte initialization vector (IV)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # pad the message to match the AES block size using PKCS7 padding
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext.encode()) + padder.finalize()

    # encrypt the padded message
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # return the IV plus the encrypted message (IV is needed for decryption)
    return iv + ciphertext

# AES decryption function
def aes_decrypt_message(ciphertext, key):
    iv = ciphertext[:16]  # get the IV from the first 16 bytes
    encrypted_data = ciphertext[16:]  # the rest is the encrypted data

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # decrypt the data
    padded_message = decryptor.update(encrypted_data) + decryptor.finalize()

    # remove padding from the decrypted message
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    message = unpadder.update(padded_message) + unpadder.finalize()

    return message.decode()

# function to get DCT coefficients from an image’s color channels
def extract_dct_color(image_path):
    """
    Extract Discrete Cosine Transform (DCT) coefficients from an image's color channels (B, G, R).

    DCT (Discrete Cosine Transform) is a mathematical process that changes data (like image pixels)
    from the regular image format (spatial domain) into frequency values (frequency domain).

    In JPEG compression, DCT is used to break down 8x8 pixel blocks into frequency values called coefficients.
    Most of the key visual details are found in the lower frequencies, while higher frequencies are less noticeable 
    to the human eye. This helps JPEG compress images by removing higher frequency details that don't affect the overall quality as much.

    We use DCT here because JPEG already uses this method for compression, and it is a good spot to hide data in 
    the low-frequency coefficients without changing the way the image looks too much.
    """
    # load the image using OpenCV (in BGR format by default)
    image = cv2.imread(image_path)

    # split the image into its color channels (Blue, Green, Red)
    channels = cv2.split(image)
    
    dct_coefficients = []  # list to store the DCT values for each color channel
    shapes = []  # list to store the size of each channel (height, width)

    # for each color channel, apply the DCT in 8x8 pixel blocks (how JPEG handles compression)
    for channel in channels:
        height, width = channel.shape
        shapes.append(channel.shape)  # store the shape for later use
        dct_channel = []  # list to hold the DCT coefficients for this channel

        # go through the image in 8x8 pixel blocks
        for i in range(0, height, 8):
            for j in range(0, width, 8):
                block = channel[i:i+8, j:j+8]  # get a small 8x8 block
                dct_block = cv2.dct(np.float32(block))  # apply DCT to the block
                dct_channel.append(dct_block)  # save the DCT-transformed block
        dct_coefficients.append(np.array(dct_channel))  # save all blocks for this channel

    return dct_coefficients, shapes  # return the DCT values and the shapes of each channel

# function to hide a message inside the DCT coefficients
def embed_data_in_dct(dct_coefficients, message):
    """
    Hide a message into the DCT coefficients of an image by altering the least significant bits (LSB) 
    of the low-frequency DCT values.

    Since the low-frequency DCT coefficients capture most of the important visual details of the image,
    making slight changes to their least significant bits allows data to be embedded without creating any
    noticeable changes in the image's appearance.

    By hiding the message in the low-frequency DCT coefficients, it's less likely to be impacted by JPEG's 
    lossy compression. JPEG typically removes high-frequency DCT values while retaining low-frequency ones 
    to preserve image quality. Since we are modifying the low-frequency coefficients, the hidden data stays 
    intact even after the image undergoes JPEG compression.

    This approach is commonly used in JPEG steganography because it ensures that the embedded message 
    survives compression with minimal visual changes or data loss.
    """
    # turn the message into binary (each character becomes an 8-bit binary number)
    binary_message = ''.join(format(ord(char), '08b') for char in message)

    message_idx = 0  # this tracks where we are in the binary message

    # go through each DCT block
    for block in dct_coefficients:
        # only modify the first few low-frequency DCT values (skip the very first one, which is the DC component)
        for coeff_idx in range(1, min(6, len(block.flatten()))):
            coeff = np.int32(block.flat[coeff_idx])  # get the current DCT value as an integer
            
            if message_idx < len(binary_message):
                # change the least significant bit (LSB) based on the current bit of the message
                if binary_message[message_idx] == '1':
                    coeff = coeff | 1  # set LSB to 1
                else:
                    coeff = coeff & ~1  # set LSB to 0

                # put the modified coefficient back into the block
                block.flat[coeff_idx] = np.float32(coeff)
                message_idx += 1  # move to the next bit of the message

            # stop if we’ve embedded the whole message
            if message_idx >= len(binary_message):
                break

        if message_idx >= len(binary_message):
            break

    return dct_coefficients  # return the modified DCT coefficients with the hidden message

# function to extract the hidden message from the DCT coefficients
def extract_data_from_dct(dct_coefficients, message_length):
    """
    Extract the hidden message by reading the least significant bits (LSBs) of the low-frequency
    DCT coefficients.
    """
    bits = []  # list to store the extracted bits
    message_idx = 0  # this tracks how many bits we’ve read
    
    # go through each DCT block
    for block in dct_coefficients:
        # read the bits from the low-frequency DCT values (skip the first one)
        for coeff_idx in range(1, min(6, len(block.flatten()))):
            coeff = np.int32(block.flat[coeff_idx])  # get the DCT value as an integer
            
            if message_idx < message_length * 8:  # each character is 8 bits, so message_length * 8 bits total
                bits.append(coeff & 1)  # extract the least significant bit (LSB)
                message_idx += 1  # move to the next bit

            # stop if we’ve read enough bits for the message
            if message_idx >= message_length * 8:
                break

        if message_idx >= message_length * 8:
            break

    # convert the bits back to characters (8 bits = 1 byte = 1 character)
    binary_message = ''.join(str(bit) for bit in bits)
    message = ''.join(chr(int(binary_message[i:i+8], 2)) for i in range(0, len(binary_message), 8))

    return message  # return the extracted message

# function to rebuild the image after modifying the DCT coefficients
def rebuild_image_from_dct_color(dct_coefficients, shapes, output_image_path):
    """
    Rebuild an image from the modified DCT coefficients after embedding a message. This function
    applies the inverse DCT to turn the frequency data back into pixel values and saves the image.
    """
    rebuilt_channels = []  # list to hold the color channels (B, G, R)

    # go through each of the 3 color channels (Blue, Green, Red)
    for k in range(3):
        height, width = shapes[k]  # get the shape of the current channel (height, width)
        rebuilt_channel = np.zeros((height, width), dtype=np.float32)  # create an empty array for the channel
        dct_channel = dct_coefficients[k]  # get the DCT coefficients for this channel
        block_idx = 0  # track the block index

        # go through the DCT blocks and apply inverse DCT to rebuild the channel
        for i in range(0, height, 8):
            for j in range(0, width, 8):
                block = dct_channel[block_idx].astype(np.float32)  # make sure the block is in float32 format
                idct_block = cv2.idct(block)  # apply inverse DCT to convert back to pixel values
                rebuilt_channel[i:i+8, j:j+8] = idct_block  # place the rebuilt block into the channel
                block_idx += 1

        # clip the values to the valid pixel range [0, 255] and convert to uint8 (standard pixel format)
        rebuilt_channels.append(np.clip(rebuilt_channel, 0, 255).astype(np.uint8))

    # merge the color channels back into a BGR image
    rebuilt_image = cv2.merge(rebuilt_channels)

    # convert BGR to RGB (because OpenCV uses BGR by default) and save the image using Pillow
    output_image = Image.fromarray(cv2.cvtColor(rebuilt_image, cv2.COLOR_BGR2RGB))
    output_image.save(output_image_path)  # save the image
    print('\n' + '=' * 40, "\n        STEGO IMAGE CREATION PROCESS", "\n" + '=' * 40)
    print(f"Stego image saved to {output_image_path}")

def main():
    # define input and output paths using the BASE variable (works on any operating system)
    input_image_path = os.path.join(BASE, 'input', 'task6_input_image.jpeg')
    output_image_path = os.path.join(BASE, 'output', 'task6_stego_image.jpeg')

    # get the secret message from the user
    original_message = input("Enter the secret message you want to hide: ")

    # generate a random 256-bit AES key (32 bytes)
    key = urandom(32)

    # encrypt the message using AES encryption
    encrypted_message = aes_encrypt_message(original_message, key)

    # convert the encrypted message to base64 so it can be embedded as text
    encrypted_message_str = b64encode(encrypted_message).decode('utf-8')

    # Print the encrypted message in base64 string
    print('\n' + '=' * 40, "\n        ENCRYPTION PROCESS", "\n" + '=' * 40)
    print(f"Encrypted Message (Base64 String): {encrypted_message_str}")

    # extract DCT coefficients from the color channels of the input image
    dct_coefficients, image_shapes = extract_dct_color(input_image_path)

    # embed the encrypted message into the DCT coefficients of the blue channel
    modified_dct = embed_data_in_dct(dct_coefficients[0], encrypted_message_str)
    dct_coefficients[0] = modified_dct  # Update DCT coefficients of the blue channel

    # rebuild the image with the modified DCT coefficients and save it
    rebuild_image_from_dct_color(dct_coefficients, image_shapes, output_image_path)

    # extract the hidden encrypted message from the blue channel
    extracted_encrypted_message_str = extract_data_from_dct(modified_dct, len(encrypted_message_str))

    # Print the extracted encrypted message (Base64)
    print('\n' + '=' * 40, "\n        EXTRACTION PROCESS", "\n" + '=' * 40)
    print(f"Extracted Encrypted Message (Base64 String): {extracted_encrypted_message_str}")

    # decode the extracted message from base64 back to bytes
    extracted_encrypted_message = b64decode(extracted_encrypted_message_str)

    # decrypt the extracted encrypted message
    decrypted_message = aes_decrypt_message(extracted_encrypted_message, key)
    
    print('\n' + '=' * 40, "\n        DECRYPTION PROCESS", "\n" + '=' * 40)
    print(f"Decrypted Message: {decrypted_message}")

if __name__ == "__main__":
    main()
