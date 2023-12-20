class AES_128():
    def __init__(self):
        self.state = [0] * 16

    Sbox = (
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
            0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
            0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
            0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
            0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
            0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
            0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
            0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
            0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
            0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
            0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
            0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
    )

    Rcon = ( 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a )
    
    @staticmethod
    def rot_word(word):
        return word[1:] + word[:1]

    @staticmethod
    def sub_word(word):
        return (AES_128.Sbox[b] for b in word)
    
    @staticmethod
    def Xor(s1, s2):
        return tuple(a^b for a,b in zip(s1, s2))
    
    def GMul(self,a,b):
        p = 0
        for c in range(8):
            if b & 1:
                p ^= a
            a <<= 1
            if (a & 0x100): # if we encounter x^8, use irreducible polynomial theorem x^8 = x^4 + x^3 + x + 1
                a ^= 0x11b
            b >>=1
        return p
    

    def subBytes(self, state):
        return [[hex(AES_128.Sbox[int(j, 16)])[2:].zfill(2) for j in row] for row in state]

    def shiftRows(self, state):
        # return [state[i][i:] + state[i][:i] for i in range(4)]
        
        # Transpose the state to make column operations easier
        state = list(map(list, zip(*state)))

        # Shift each column by its index
        state = [state[i][i:] + state[i][:i] for i in range(4)]

        # Transpose the state back to its original form
        state = list(map(list, zip(*state)))
        return state

    def mixColumn(self, state):
        state = list(map(list, zip(*state)))
        s = [[int(j, 16) for j in row] for row in state]
        for c in range(4):
            s0 = self.GMul(0x02, s[0][c]) ^ self.GMul(0x03, s[1][c]) ^ s[2][c] ^ s[3][c]
            s1 = s[0][c] ^ self.GMul(0x02, s[1][c]) ^ self.GMul(0x03, s[2][c]) ^ s[3][c]
            s2 = s[0][c] ^ s[1][c] ^ self.GMul(0x02, s[2][c]) ^ self.GMul(0x03, s[3][c])
            s3 = self.GMul(0x03, s[0][c]) ^ s[1][c] ^ s[2][c] ^ self.GMul(0x02, s[3][c])

            s[0][c] = hex(s0)[2:].zfill(2)
            s[1][c] = hex(s1)[2:].zfill(2)
            s[2][c] = hex(s2)[2:].zfill(2)
            s[3][c] = hex(s3)[2:].zfill(2)
        s = list(map(list, zip(*s)))
        return s

    def add_round_key(self, state, rKey):
        return [[hex((int(i, 16) if isinstance(i, str) else i) ^ (int(j, 16) if isinstance(j, str) else j))[2:].zfill(2) for i, j in zip(row, key_row)] for row, key_row in zip(state, rKey)]

    def keyScheduling(self, key):
        allKeys = []
        allKeys.append(key)
        R = 11

        for i in range(1, R):
            t = allKeys[-1]  # Get the last 4x4 key
            t0 = self.Xor(self.sub_word(self.rot_word(t[3])), [self.Rcon[i], 0, 0, 0])  # First column of new key
            t0 = self.Xor(t0,t[0])
            t1 = self.Xor(t0, t[1])  # Second column of new key
            t2 = self.Xor(t1, t[2])  # Third column of new key
            t3 = self.Xor(t2, t[3])  # Fourth column of new key
            newKey = [t0, t1, t2, t3]  # New 4x4 key
            # print(''.join(''.join(format(byte, '02x') for byte in row) for row in newKey))
            allKeys.append(newKey)        
        return allKeys
    
    def printState(self):
        for row in range(4):
            for col in range(4):
                index = col + row * 4
                print(format(self.state[index], '02x'), end=' ')
            print()

    def encrypt(self, plaintext, key):
        state = [[int(plaintext[i:i+2], 16) for i in range(j, j+8, 2)] for j in range(0, 32, 8)]
        key = [[int(key[i:i+2], 16) for i in range(j, j+8, 2)] for j in range(0, 32, 8)]
        keys = self.keyScheduling(key)    
        state = self.add_round_key(state, keys[0])
        
        for r in range(1,10):  
            state = self.subBytes(state)
            state = self.shiftRows(state)
            state = self.mixColumn(state)
            state = self.add_round_key(state, keys[r])


        state = self.subBytes(state)
        state = self.shiftRows(state)
        state = self.add_round_key(state, keys[10])
        return ''.join(''.join(row) for row in state)
    
    inv_Sbox = (
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, 
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    )

    def inverse_subBytes(self, state):
        return [[hex(AES_128.inv_Sbox[int(j, 16)])[2:].zfill(2) for j in row] for row in state]

    def inverse_shiftRows(self, state):
        state = list(map(list, zip(*state)))
        
        state = [state[i][-i:] + state[i][:-i] for i in range(4)]

        state = list(map(list, zip(*state)))
        return state

    def inverse_mixColumn(self, state):
        state = list(map(list, zip(*state)))
        s = [[int(j, 16) for j in row] for row in state]
        for c in range(4):
            s0 = self.GMul(0x0e, s[0][c]) ^ self.GMul(0x0b, s[1][c]) ^ self.GMul(0x0d, s[2][c]) ^ self.GMul(0x09, s[3][c])
            s1 = self.GMul(0x09, s[0][c]) ^ self.GMul(0x0e, s[1][c]) ^ self.GMul(0x0b, s[2][c]) ^ self.GMul(0x0d, s[3][c])
            s2 = self.GMul(0x0d, s[0][c]) ^ self.GMul(0x09, s[1][c]) ^ self.GMul(0x0e, s[2][c]) ^ self.GMul(0x0b, s[3][c])
            s3 = self.GMul(0x0b, s[0][c]) ^ self.GMul(0x0d, s[1][c]) ^ self.GMul(0x09, s[2][c]) ^ self.GMul(0x0e, s[3][c])

            s[0][c] = hex(s0)[2:].zfill(2)
            s[1][c] = hex(s1)[2:].zfill(2)
            s[2][c] = hex(s2)[2:].zfill(2)
            s[3][c] = hex(s3)[2:].zfill(2)
        s = list(map(list, zip(*s)))
        return s
    
    def decrypt(self, ciphertext, key):
        # Assuming you have a function to generate round keys
        key = [[int(key[i:i+2], 16) for i in range(j, j+8, 2)] for j in range(0, 32, 8)]

        round_keys = self.keyScheduling(key)

        # Convert ciphertext to state matrix
        state = [[int(ciphertext[i:i+2], 16) for i in range(j, j+8, 2)] for j in range(0, 32, 8)]

        state = self.add_round_key(state, round_keys[-1])

        # 9 rounds of decryption
        for i in range(9, 0, -1):
            state = self.inverse_shiftRows(state)
            state = self.inverse_subBytes(state)
            state = self.add_round_key(state, round_keys[i])
            state = self.inverse_mixColumn(state)

        # Final round of decryption
        state = self.inverse_shiftRows(state)
        state = self.inverse_subBytes(state)
        state = self.add_round_key(state, round_keys[0])

        # Convert state matrix to plaintext
        return ''.join(''.join(row) for row in state)


if __name__ == "__main__":
    aes = AES_128()

    # key = '2b7e151628aed2a6abf7158809cf4f3c'
    # plaintext = '3243f6a8885a308d313198a2e0370734'
    # expected_ciphertext = '3925841d02dc09fbdc118597196a0b32'

    key = input("Enter a 128-bit hexadecimal (32 characters) KEY for encryption/decryption: ")
    while len(key) != 32:
        print("Key must be 128-bit (32 characters) hexadecimal long.")
        key = input("Enter a 128-bit (32 characters) hexadecimal for encryption/decryption: ")


    choice = input("Do you want to (E)ncrypt or (D)ecrypt? ")
    while choice not in ['E', 'D']:
        print("Invalid choice. Please enter E for Encrypt or D for Decrypt.")
        choice = input("Do you want to (E)ncrypt or (D)ecrypt? ")

    if choice == 'E':
        plaintext = input("Enter a 128-bit (32 characters) hexadecimal for encryption: ")
        while len(plaintext) != 32:
            print("Plaintext must be 128-bit (32 characters) hexadecimal long.")
            plaintext = input("Enter a 128-bit (32 characters) hexadecimal plaintext for encryption: ")

        # Encrypt the plaintext
        ciphertext = aes.encrypt(plaintext, key)
        print("Encrypted text is: ", ciphertext)

    else:
        ciphertext = input("Enter a 128-bit (32 characters) hexadecimal ciphertext for decryption: ")
        while len(ciphertext) != 32:
            print("Ciphertext must be 128-bit (32 characters) hexadecimal long.")
            ciphertext = input("Enter a 128-bit (32 characters) hexadecimal ciphertext for decryption: ")

        # Decrypt the ciphertext
        dec_plaintext = aes.decrypt(ciphertext, key)

        print("Decrypted text is: ", dec_plaintext)