from PIL import Image
import numpy as np
from functions import AES_128

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

    # Encrypt in 16-byte blocks (AES-128 block size)
    encrypted_data = []
    for i in range(0, len(padded_data), 16):
        block = padded_data[i:i + 16].tolist()
        plaintext = ''.join(f'{byte:02x}' for byte in block)  # Convert block to hex string
        ciphertext = aes.encrypt(plaintext, key)
        encrypted_data.extend([int(ciphertext[j:j + 2], 16) for j in range(0, len(ciphertext), 2)])

    # Trim encrypted data to match original shape (ignoring padding)
    encrypted_image_data = np.array(encrypted_data[:len(flat_data)]).reshape(original_shape)
    encrypted_image = Image.fromarray(np.uint8(encrypted_image_data))
    encrypted_image.save('encrypted_image.png')

# Example usage
image_path = 'image.png'  # Path to your input image
key = '2b7e151628aed2a6abf7158809cf4f3c'  # Example 128-bit key
encrypt_image(image_path, key)
