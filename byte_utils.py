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

import sys
import numpy as np
PY2 = sys.version_info[0] == 2; PY3 = sys.version_info[0] == 3

if PY2:
    import array
#print (PY2, PY3)
if PY3:
    xrange = range

def bytes_from_hex(hex_str):
    if PY2:
        return array.array("B", hex_str.decode('hex'))
    if PY3:
        return bytes.fromhex(hex_str)

def print_hex_str(hex_str, msg=''):
    print(msg, list(map(hex, hex_str)))

def bytes_to_word(bytes_arr):
    word = bytes_arr[0] << 24
    word ^= bytes_arr[1] << 16
    word ^= bytes_arr[2] << 8
    word ^= bytes_arr[3]
    return word

def word_to_bytes(word):
    bytes_arr = np.zeros(4, dtype=np.uint8)
    bytes_arr[0] = (word >> 24) & 0xff
    bytes_arr[1] = (word >> 16) & 0xff
    bytes_arr[2] = (word >> 8) & 0xff
    bytes_arr[3] = (word >> 0) & 0xff
    return bytes_arr

def word_to_bytes_LE(word):
    bytes_arr = np.zeros(4, dtype=np.uint8)
    bytes_arr[3] = (word >> 24) & 0xff
    bytes_arr[2] = (word >> 16) & 0xff
    bytes_arr[1] = (word >> 8) & 0xff
    bytes_arr[0] = (word >> 0) & 0xff
    return bytes_arr

def u64_to_bytes_LE(word):
    bytes_arr = np.zeros(8, dtype=np.uint8)
    bytes_arr[7] = (word >> 56) & 0xff
    bytes_arr[6] = (word >> 48) & 0xff
    bytes_arr[5] = (word >> 40) & 0xff
    bytes_arr[4] = (word >> 32) & 0xff
    bytes_arr[3] = (word >> 24) & 0xff
    bytes_arr[2] = (word >> 16) & 0xff
    bytes_arr[1] = (word >> 8) & 0xff
    bytes_arr[0] = (word >> 0) & 0xff
    return bytes_arr
