# Resource: https://www.youtube.com/watch?v=-fpVv_T4xwA&ab_channel=Computerphile
import os
from PIL import Image
import numpy as np
from functions import AES_128


class AES_128_GCM(AES_128):
    def encrypt_gcm(self, plaintext, key, nonce):
        """
        Encrypts the plaintext using AES in GCM mode.

        :param plaintext: Hex string plaintext to encrypt
        :param key: Hex string key (128-bit)
        :param nonce: Randomly generated nonce (12-byte recommended for GCM)
        :return: Ciphertext and authentication tag as hex strings
        """
        # Convert plaintext to bytes
        plaintext_bytes = bytes.fromhex(plaintext)
        key_bytes = bytes.fromhex(key)
        
        # Initialize counter with the nonce
        counter = int.from_bytes(nonce, byteorder='big')
        
        # Encrypt in counter mode
        ciphertext = bytearray(len(plaintext_bytes))
        for i in range(0, len(plaintext_bytes), 16):
            # Prepare counter block and encrypt it
            counter_block = counter.to_bytes(16, byteorder='big')
            encrypted_counter = self.encrypt(counter_block.hex(), key)
            
            # XOR the encrypted counter with the plaintext block
            for j in range(min(16, len(plaintext_bytes) - i)):
                ciphertext[i + j] = plaintext_bytes[i + j] ^ int(encrypted_counter[j * 2:(j + 1) * 2], 16)
            
            # Increment counter
            counter += 1
        
        auth_tag = self.generate_auth_tag(ciphertext, key_bytes)

        return ciphertext.hex(), auth_tag.hex()

    def galois_multiply(self, x, y):
        """
        Multiplies two 128-bit values in GF(2^128) using the Galois Field multiplication algorithm.

        :param x: 128-bit integer (usually the hash subkey)
        :param y: 128-bit integer (the input block to multiply)
        :return: Result of the Galois Field multiplication as a 128-bit integer
        """
        # Irreducible polynomial for GF(2^128)
        r = 0xE1000000000000000000000000000000  # Equivalent to x^128 + x^7 + x^2 + x + 1

        result = 0
        for i in range(128):
            if y & (1 << (127 - i)):  # If the current bit of y is set
                result ^= x
            # Check if the leftmost bit of x is set
            if x & (1 << 127):
                x = (x << 1) ^ r  # Shift left and reduce with the polynomial
            else:
                x <<= 1

            # Keep x as a 128-bit value
            x &= (1 << 128) - 1

        return result

    def generate_auth_tag(self, ciphertext, key_bytes):
        """
        Generates an authentication tag using the Galois Field multiplication approach.

        :param ciphertext: Bytearray containing the encrypted data
        :param key_bytes: Bytearray containing the AES key (used to derive the hash subkey)
        :return: 128-bit authentication tag as a bytes object
        """
        # Derive the hash subkey (H) by encrypting an all-zero block with AES
        zero_block = '00' * 16
        H = int(self.encrypt(zero_block, key_bytes.hex()), 16)

        # Initialize the authentication tag as zero
        auth_tag = 0

        # Process each 128-bit block of ciphertext
        for i in range(0, len(ciphertext), 16):
            block = int.from_bytes(ciphertext[i:i+16], byteorder='big')
            # XOR the current block with the running authentication tag
            auth_tag ^= block
            # Multiply the result by H in the Galois Field
            auth_tag = self.galois_multiply(auth_tag, H)

        # Convert the authentication tag to bytes
        return auth_tag.to_bytes(16, byteorder='big')

def encrypt_image_gcm(image_path, key):
    # Create an AES instance
    aes_gcm = AES_128_GCM()

    # Ensure the key is 16 bytes for AES-128
    key_bytes = key

    # Generate a random 12-byte nonce for GCM
    nonce = os.urandom(12)

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

    # Encrypt the padded data
    ciphertext, auth_tag = aes_gcm.encrypt_gcm(
        plaintext=padded_data.tobytes().hex(),
        key=key,
        nonce=nonce
    )

    # Convert ciphertext back to a NumPy array and reshape to original image dimensions
    encrypted_data = bytes.fromhex(ciphertext)
    encrypted_image_data = np.frombuffer(encrypted_data[:len(flat_data)], dtype=np.uint8).reshape(original_shape)
    encrypted_image = Image.fromarray(np.uint8(encrypted_image_data))
    encrypted_image.save('encrypted_image_gcm.png')

    # Save nonce and auth tag for decryption purposes
    with open('gcm_data.bin', 'wb') as f:
        f.write(nonce + bytes.fromhex(auth_tag))

# Example usage
image_path = 'image.png'  # Path to your input image
key = '2b7e151628aed2a6abf7158809cf4f3c'  # Example 128-bit key
encrypt_image_gcm(image_path, key)
