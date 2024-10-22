from PIL import Image
import numpy as np
from functions import AES_128

def xor_blocks(block1, block2):
    """XOR two byte arrays."""
    return [b1 ^ b2 for b1, b2 in zip(block1, block2)]

def encrypt_image(image_path, key):
    # Initialize AES-128 instance
    aes = AES_128()

    # Open the image and convert it to a byte array
    image = Image.open(image_path).convert('L')  # Convert to grayscale
    image_data = np.array(image)

    # Store the original shape
    original_shape = image_data.shape

    # Flatten the image data
    flat_data = image_data.flatten()

    # Ensure the data length is a multiple of 16 for AES block size
    padding_length = (16 - (len(flat_data) % 16)) % 16
    padded_data = np.pad(flat_data, (0, padding_length), mode='constant', constant_values=0)

    # Define an IV (Initialization Vector)
    iv = [0x00] * 16  # Example IV, should be randomly generated in real scenarios

    # Encrypt in CBC mode (AES-128 block size of 16 bytes)
    previous_cipher_block = iv
    encrypted_data = []
    for i in range(0, len(padded_data), 16):
        block = padded_data[i:i + 16].tolist()
        
        # XOR the plaintext block with the previous ciphertext block (or IV for the first block)
        xor_block = xor_blocks(block, previous_cipher_block)

        # Convert XOR result to hex string
        plaintext = ''.join(f'{byte:02x}' for byte in xor_block)
        
        # Encrypt the XORed block
        ciphertext = aes.encrypt(plaintext, key)

        # Convert ciphertext back to integers
        encrypted_block = [int(ciphertext[j:j + 2], 16) for j in range(0, len(ciphertext), 2)]
        
        # Update the previous cipher block for the next iteration
        previous_cipher_block = encrypted_block

        # Append encrypted block to the result
        encrypted_data.extend(encrypted_block)

    # Trim encrypted data to match original shape (ignoring padding)
    encrypted_image_data = np.array(encrypted_data[:len(flat_data)]).reshape(original_shape)
    encrypted_image = Image.fromarray(np.uint8(encrypted_image_data))
    encrypted_image.save('encrypted_image_cbc.png')

# Example usage
image_path = 'image.png'  # Path to your input image
key = '2b7e151628aed2a6abf7158809cf4f3c'  # Example 128-bit key
encrypt_image(image_path, key)
