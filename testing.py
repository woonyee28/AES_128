import unittest
from functions import AES_128

class AESTestCase(unittest.TestCase):
    def test_encryption_and_decryption(self):
        aes = AES_128()
        key = '2b7e151628aed2a6abf7158809cf4f3c'
        plaintext = '3243f6a8885a308d313198a2e0370734'
        expected_ciphertext = '3925841d02dc09fbdc118597196a0b32'

        # Encrypt the plaintext and check if it matches the expected ciphertext
        ciphertext = aes.encrypt(plaintext, key)
        self.assertEqual(ciphertext, expected_ciphertext)


    def test_subbytes(self):
        aes = AES_128()
        state = [
            ['19', 'a0', '9a', 'e9'],
            ['3d', 'f4', 'c6', 'f8'],
            ['e3', 'e2', '8d', '48'],
            ['be', '2b', '2a', '08']
        ]
        expected_result = [
            ['d4', 'e0', 'b8', '1e'],
            ['27', 'bf', 'b4', '41'],
            ['11', '98', '5d', '52'],
            ['ae', 'f1', 'e5', '30']
        ]
        result = aes.subBytes(state)
        self.assertEqual(result, expected_result)

    def test_shiftrows(self):
        aes = AES_128()
        state = [
            ['d4', '27', '11', 'ae'],
            ['e0', 'bf', '98', 'f1'],
            ['b8', 'b4', '5d', 'e5'],
            ['1e', '41', '52', '30']
        ]
        expected_result = [
            ['d4', 'bf', '5d', '30'],
            ['e0', 'b4', '52', 'ae'],
            ['b8', '41', '11', 'f1'],
            ['1e', '27', '98', 'e5']
        ]
        result = aes.shiftRows(state)
        self.assertEqual(result, expected_result)

    def test_mixcolumn(self):
        aes = AES_128()
        state = [
            ['d4', 'bf', '5d', '30'],
            ['e0', 'b4', '52', 'ae'],
            ['b8', '41', '11', 'f1'],
            ['1e', '27', '98', 'e5']
        ]
        expected_result = [
            ['04', '66', '81', 'e5'],
            ['e0', 'cb', '19', '9a'],
            ['48', 'f8', 'd3', '7a'],
            ['28', '06', '26', '4c']
        ]
        result = aes.mixColumn(state)
        self.assertEqual(result, expected_result)

    def test_addroundkey(self):
        aes = AES_128()
        state = [
            ['04', 'e0', '48', '28'],
            ['66', 'cb', 'f8', '06'],
            ['81', '19', 'd3', '26'],
            ['e5', '9a', '7a', '4c']
        ]
        round_key = [
            ['a0', '88', '23', '2a'],
            ['fa', '54', 'a3', '6c'],
            ['fe', '2c', '39', '76'],
            ['17', 'b1', '39', '05']
        ]
        expected_result = [
            ['a4', '68', '6b', '02'],
            ['9c', '9f', '5b', '6a'],
            ['7f', '35', 'ea', '50'],
            ['f2', '2b', '43', '49']
        ]
        result = aes.add_round_key(state, round_key)
        self.assertEqual(result, expected_result)

if __name__ == '__main__':
    unittest.main()




