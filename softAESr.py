# Copyright (C) 2019 Eyal Ronen <er [at] eyalro [dot] net>

# This file is a part of the AES-Cryptoanalysis code.

# This file may be used under the terms of the GNU General Public License
# version 3 as published by the Free Software Foundation and appearing in
# the file LICENSE.GPL included in the packaging of this file.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

#This file implements reduced round version of AES. Based on softAES.py
from softAES import _compact_word, AES
import copy
import array
from byte_utils import bytes_from_hex, print_hex_str

class AESr(AES):
    def __init__(self, key, rounds):
        super(AESr, self).__init__(key)
        self._Ke =  self._Ke[0:rounds+1]
        self._Kd  = self._Kd[-(rounds+1):]
        #remove XOR of key in last round, makes it easier to work with
        self.final_round_key = self._Ke[-1]
        self._Ke[-1] = [0] * 4
        self._Kd[0] = [0] * 4

    def encrypt_r(self, plaintext, rounds, xorlastroundkey=True):
        'Encrypt a block of plain text using the AES block cipher.'

        if len(plaintext) != 16:
            print ('plaintrex len', len(plaintext))
            raise ValueError('wrong block length')
        rounds += 1
        if rounds > len(self._Ke) :
            raise Exception("not enough key for partial encryption")

        (s1, s2, s3) = [1, 2, 3]
        a = [0, 0, 0, 0]

        # Convert plaintext to (ints ^ key)
        t = [(_compact_word(plaintext[4 * i:4 * i + 4]) ^ self._Ke[0][i]) for i in xrange(0, 4)]

        # Apply round transforms
        for r in xrange(1, rounds):
            for i in xrange(0, 4):
                a[i] = (self.T1[(t[ i          ] >> 24) & 0xFF] ^
                        self.T2[(t[(i + s1) % 4] >> 16) & 0xFF] ^
                        self.T3[(t[(i + s2) % 4] >>  8) & 0xFF] ^
                        self.T4[ t[(i + s3) % 4]        & 0xFF] ^
                        self._Ke[r][i])
            t = copy.copy(a)
        # The last round is special
        result = [ ]

        if not xorlastroundkey:
            for i in xrange(0, 4):
                t[i] = t[i] ^ self._Ke[rounds-1][i]


        for i in xrange(0, 4):
            result.append((t[i] >> 24) & 0xFF)
            result.append((t[i] >> 16) & 0xFF)
            result.append((t[i] >> 8) & 0xFF)
            result.append(t[i]        & 0xFF)



        return result



    def encrypt_raw_r(self, plaintext, rounds):
        plaintext_arr = array.array('B', plaintext)
        res_array = self.encrypt_r(plaintext_arr, rounds)
        return "".join(map(chr, res_array))

    def get_round_key(self, round):
        return self._Ke[round]

    def get_round_key_bytes(self, round):
        byte_list = []
        for i in range(4):
            word = self._Ke[round][i]
            byte_list.append((word >> 24) & 0xff)
            byte_list.append((word >> 16) & 0xff)
            byte_list.append((word >> 8) & 0xff)
            byte_list.append((word >> 0) & 0xff)
        return byte_list

    def get_round_key_byte(self, round, byte):
        word = int(byte / 4)
        round_key = self.get_round_key(round)
        keyword = round_key[word]
        keybyte = (keyword >> ((3-byte % 4) * 8)) & 0xff
        return keybyte



if __name__ == '__main__':
    p = '00112233445566778899aabbccddeeff'
    key = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
    c = '8ea2b7ca516745bfeafc49904b496089'
    r5 = 'c357aae11b45b7b0a2c7bd28a8dc99fa'
    r5 = 'aeb65ba974e0f822d73f567bdb64c877'
    r5 = '9cf0a62049fd59a399518984f26be178'
    keyarr = bytes_from_hex(key)
    parr = bytes_from_hex(p)
    print (parr)
    print (len(keyarr), keyarr)
    print (len(parr), parr)
    aes = AESr(keyarr, 5)
    #aes = AES(keyarr)
    r5calc =  aes.encrypt(parr)
    pcalc = aes.decrypt(r5calc)
    r1calc = aes.encrypt_r(parr, 1)
    r2calc = aes.encrypt_r(parr, 2)
    r3calc = aes.encrypt_r(parr, 5)
    print_hex_str(r5calc, 'r5calc')
    print_hex_str(bytes_from_hex(r5), 'r5    ')

    print_hex_str(pcalc)
    print_hex_str(r1calc)
    print_hex_str(r2calc)
    print_hex_str(r3calc)

    #test aes 128
    print ('test aes 128')
    key = '000102030405060708090a0b0c0d0e0f'
    keyarr = bytes_from_hex(key)
    aes = AESr(keyarr, 10)
    aes_full = AES(keyarr)
    cipher = aes_full.encrypt(parr)
    #gives us the full encryption without xoring the last round key
    r10calc = aes.encrypt(parr)
    r9calc = aes.encrypt_r(parr, 9)
    r9calcnoround = aes.encrypt_r(parr, 9, False)
    pcalc = aes_full.decrypt(cipher)
    r1calc = aes.encrypt_r(parr, 1)
    r2calc = aes.encrypt_r(parr, 2)
    r3calc = aes.encrypt_r(parr, 5)
    print('full encryption ' ,map(hex, cipher))
    print ('no last round key ' ,map(hex, r10calc))
    print ('after full 9 rounds ', map(hex, r9calc))
    print ('after full 9 rounds no round 9 key ', map(hex, r9calcnoround))
    print (list(map(hex, pcalc)))
    print (list(map(hex, r1calc)))
    print (list(map(hex, r2calc)))
    print (list(map(hex, r3calc)))
    print (list(map(hex, aes.get_round_key(9))))
    print (list(map(hex, aes.final_round_key)))

    print ('test get key')
    print (list(map(hex, keyarr)))
    key_round_0 = aes.get_round_key(0)
    for i in range(len(keyarr)):
        print (hex(aes.get_round_key_byte(0,i)),)
    print ('')
    for i in range(len(key_round_0)):
        print (hex(key_round_0[i]),)
    print( '')

