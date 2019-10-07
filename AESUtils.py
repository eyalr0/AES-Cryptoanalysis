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

from softAES import AES
import struct
import numpy as np

SBOX = np.array(AES.S, dtype=np.uint8)

def encrypt_col_str(col, k0,k5, k10,k15):
    return encrypt_col(col[0],col[1],col[2],col[3], k0,k5, k10,k15)

def get_key_byte(key_str, index):
    return int(key_str[index*2:index*2+2], 16)


def encrypt_col(x,y,z,w, k0,k5, k10,k15):
    return (AES.T1[x^k0] ^
            AES.T2[y^k5] ^
            AES.T3[z^k10] ^
            AES.T4[w^k15])

def aes_col(bytes_arr):
    res = AES.T1[bytes_arr[0]]
    res ^= AES.T2[bytes_arr[1]]
    res ^= AES.T3[bytes_arr[2]]
    res ^= AES.T4[bytes_arr[3]]
    return res

def encrypt_col_to_bytes(x,y,z,w, k0,k1, k2,k3):
    res = (AES.T1[x] ^
            AES.T2[y] ^
            AES.T3[z] ^
            AES.T4[w])
    print (hex(res))
    bytes = list(struct.unpack("4B", struct.pack("I", res)))
    bytes.reverse()
    print (map(hex, bytes))
    bytes[0] = bytes[0] ^ k0
    bytes[1] = bytes[1] ^ k1
    bytes[2] = bytes[2] ^ k2
    bytes[3] = bytes[3] ^ k3
    print (map(hex, bytes))

    return bytes


def Gmul(a, b):
    px = 0x1b

    p = 0
    for i in range(8):
      if ((b & 1) == 1):
          p ^= a
      high = (a & 0x80)
      a <<= 1
      a &= 0xff
      if(high == 0x80):
          a ^= px
      b >>= 1

    return p

def getGmulInv(a):
    mul = map(lambda x: Gmul(a, x), range(256))
    res = [x for x in range(256) if mul[x] == 1]
    return res[0]

def mix_col(plain, key):
    bytes = np.array(plain, dtype=np.uint8) ^ np.array(key, dtype=np.uint8)
    bytes = SBOX[bytes]
    column = [0]*4
    column[0] = (Gmul(bytes[0], 2) ^ Gmul(bytes[3], 1) ^ Gmul(bytes[2], 1) ^ Gmul(bytes[1], 3)) & 0xff
    column[1] = (Gmul(bytes[1], 2) ^ Gmul(bytes[0], 1) ^ Gmul(bytes[3], 1) ^ Gmul(bytes[2], 3)) & 0xff
    column[2] = (Gmul(bytes[2], 2) ^ Gmul(bytes[1], 1) ^ Gmul(bytes[0], 1) ^ Gmul(bytes[3], 3)) & 0xff
    column[3] = (Gmul(bytes[3], 2) ^ Gmul(bytes[2], 1) ^ Gmul(bytes[1], 1) ^ Gmul(bytes[0], 3)) & 0xff
    return np.array(column, dtype=np.uint8)

def encrypt_bytes(bytes, key_bytes):
    for i in range(len(bytes)):
        bytes[i] = AES.S[bytes[i]]

    column = [0]*4
    column[0] = (key_bytes[0] ^ Gmul(bytes[0],2) ^ Gmul(bytes[3],1) ^ Gmul(bytes[2],1) ^ Gmul(bytes[1],3)) & 0xff
    column[1] = (key_bytes[1] ^ Gmul(bytes[1], 2) ^ Gmul(bytes[0], 1) ^ Gmul(bytes[3], 1) ^ Gmul(bytes[2], 3)) & 0xff
    column[2] = (key_bytes[2] ^ Gmul(bytes[2], 2) ^ Gmul(bytes[1], 1) ^ Gmul(bytes[0], 1) ^ Gmul(bytes[3], 3)) & 0xff
    column[3] = (key_bytes[3] ^ Gmul(bytes[3], 2) ^ Gmul(bytes[2], 1) ^ Gmul(bytes[1], 1) ^ Gmul(bytes[0], 3)) & 0xff

    #print map(hex, column)
    return column

def decrypt_bytes(in_bytes, key_bytes):
    column = [0]*4
    bytes = [0]*4
    for i in range(len(bytes)):
        bytes[i] = in_bytes[i] ^ key_bytes[i]
    column[0] = (Gmul(bytes[0], 0x0E) ^ Gmul(bytes[3], 0x09) ^ Gmul(bytes[2], 0x0D) ^ Gmul(bytes[1], 0x0B)) & 0xff
    column[1] = (Gmul(bytes[1], 0x0E) ^ Gmul(bytes[0], 0x09) ^ Gmul(bytes[3], 0x0D) ^ Gmul(bytes[2], 0x0B)) & 0xff
    column[2] = (Gmul(bytes[2], 0x0E) ^ Gmul(bytes[1], 0x09) ^ Gmul(bytes[0], 0x0D) ^ Gmul(bytes[3], 0x0B)) & 0xff
    column[3] = (Gmul(bytes[3], 0x0E) ^ Gmul(bytes[2], 0x09) ^ Gmul(bytes[1], 0x0D) ^ Gmul(bytes[0], 0x0B)) & 0xff


    for i in range(len(bytes)):
        column[i] = AES.Si[column[i]]

    return column

def decrypt_state_round(bytes, key_bytes):
    input_bytes = [[0, 5, 10, 15], [4, 9, 14, 3], [8, 13, 2, 7], [12, 1, 6, 11]]
    res = [0]*16
    for word in range(4):
        dec_bytes = decrypt_bytes(bytes[word*4:word*4+4], key_bytes[word*4:word*4+4])
        for byte in  range(4):
            res[input_bytes[word][byte]] = dec_bytes[byte]
    return res

def calc_DDT_row(diff):
    x1 = np.arange(256)
    x2 = x1 ^ diff
    yxor = SBOX[x1]^SBOX[x2]
    return np.bincount(yxor)


if __name__ == '__main__':
    import array
    from softAESr import AESr
    from aes_key_schedule import keyScheduleRounds
    import numpy as np

    p = '00112233445566778899aabbccddeeff'
    key = '000102030405060708090a0b0c0d0e0f'
    keyarr = array.array("B", key.decode('hex'))
    parr = array.array("B", p.decode('hex'))
    aes = AESr(keyarr, 10)
    aes_full = AES(keyarr)
    key8 = np.array(keyScheduleRounds(keyarr, 0, 9))
    key9 = keyScheduleRounds(keyarr, 0, 9)
    r9calc = aes.encrypt_r(parr, 9)
    r8calc = np.array(aes.encrypt_r(parr, 8))
    r8test = decrypt_bytes(r9calc[0:4], key9[0:4])
    print (map(hex, r8test))
    print (map(hex, r8calc[[0, 5, 10, 15]]))
    if any(r8test != r8calc[[0, 5, 10, 15]]):
        raise Exception('Test decrypt_bytes failed!')

    r9test = encrypt_bytes(r8calc[[0,5,10,15]], key9[0:4])
    print (map(hex, r9test))
    print (map(hex, r9calc[0:4]))
    if r9test != r9calc[0:4]:
        raise Exception('Test encrypt_bytes failed!')
    r8test = decrypt_state_round(r9calc, key9)
    print (map(hex, r8test))
    print (map(hex, r8calc))
    if any(r8test != r8calc):
        raise Exception('Test encrypt_bytes failed!')