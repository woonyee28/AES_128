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

if __name__ == "__main__":
    aes = AES_128()
    key = '2b7e151628aed2a6abf7158809cf4f3c'
    plaintext = '3243f6a8885a308d313198a2e0370734'
    expected_ciphertext = '3925841d02dc09fbdc118597196a0b32'

    # Encrypt the plaintext and check if it matches the expected ciphertext
    ciphertext = aes.encrypt(plaintext, key)
    if ciphertext == expected_ciphertext:
        print("it works!")
    else:
        print("no")
        print(ciphertext)
        print(expected_ciphertext)


# https://www.cryptool.org/en/cto/aes-step-by-step