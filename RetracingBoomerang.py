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

# This file implemetns the simulation used to verify the success probability of the attack 
# as described in the paper "The Retracing Boomerang Attack" in the section "Experimental verification"

from __future__ import print_function

import numpy as np
from byte_utils import bytes_from_hex
from keys500 import key
from softAESr import AESr
from AESUtils import Gmul, getGmulInv, SBOX, mix_col
from collections import defaultdict
import pickle
import matplotlib.pyplot as plt

verbose = False
# If true use a structre for the pairs (optimize the amount of data)
struct_pairs = True
# How many cipher pairs we use to verify we got the right pair
num_cipher_for_check = 6

def calc_key_from_diff(a, b):
    res = [[]]*256
    for k in range(256):
        diff = SBOX[a^k] ^ SBOX[b^k]
        res[diff] = res[diff] + [k]
    return res

def get_col(a, num):
    if num == 0:
        return np.array([a[0],  a[5], a[10], a[15]], dtype=np.uint8)
    raise Exception("Unsupported col num")

def mixcol_first_round(p, k, col):
    plain = get_col(p,col)
    key = get_col(k, col)
    return mix_col(plain, key)


# assume zero diff in byte 0
# we know p5 = 0, and ptag5 = 0x1
def getk5(p0, ptag0, k0, diff0_index):
    global diff2k5
    diff0 = SBOX[p0^k0] ^ SBOX[ptag0^k0]
    if diff0_index == 0:
        coef0 = 2
        coef1 = 3
    if diff0_index == 1:
        coef0 = 1
        coef1 = 2
    if diff0_index == 2:
        coef0 = 1
        coef1 = 1
    if diff0_index == 3:
        coef0 = 3
        coef1 = 1
    coefInv5 = getGmulInv(coef1)
    diff5 = Gmul(coefInv5, Gmul(coef0, diff0))
    return diff2k5[diff5]

def get_key_pairs(p0, ptag0, diff0_index):
    key_pairs = {}
    for k0 in range(256):
        k5 = getk5(p0, ptag0, k0, diff0_index)
        if len(k5) == 2 or len(k5) == 4:
            key_pairs[k0] = k5
        elif len(k5) != 0:
            print (k5)
            raise Exception('get_key_pairs - len of k5 is bad')
    return key_pairs

# debug function for sanity check
def find_0diff_byte(key, pairs, diff0_index = 0):
    all0diff = []
    for j in range(len(key)):
        for i in range(len(pairs)):
            keyarr = bytes_from_hex(key[j])
            mixcol0 = mixcol_first_round(pairs[i][0], keyarr, 0)
            mixcol1 = mixcol_first_round(pairs[i][1], keyarr, 0)
            diff = mixcol0 ^ mixcol1
            if diff[diff0_index] == 0:
                all0diff.append([j, i])
    return all0diff

def get_mixture(x,y):
    mixx = x[:]
    mixy = y[:]

    mixx[0] = y[0]
    mixx[7] = y[7]
    mixx[10] = y[10]
    mixx[13] = y[13]

    mixy[0] = x[0]
    mixy[7] = x[7]
    mixy[10] = x[10]
    mixy[13] = x[13]

    return np.array(mixx, dtype=np.uint8), np.array(mixy, dtype=np.uint8)


def MiTM(p2, ptag2, key_pairs, key_index = 3, diff0_index = 0, col=0):
    p2col = get_col(p2, col)
    p2tagcol = get_col(ptag2, col)
    k0k5diff = defaultdict(list)
    kbytediff = defaultdict(list)
    for k0 in key_pairs.keys():
        for k5 in key_pairs[k0]:
            diff = mix_col(np.concatenate([p2col[0:2],[0,0]]), [k0, k5, 0, 0])[diff0_index]
            difftag = mix_col(np.concatenate([p2tagcol[0:2],[0,0]]), [k0, k5, 0, 0])[diff0_index]
            k0k5diff[diff^difftag].append([k0, k5])
    plain = [0] * 4
    plaintag = [0] * 4
    plain[key_index] = p2col[key_index]
    plaintag[key_index] = p2tagcol[key_index]
    key_temp = [0] * 4
    for key_byte in range(256):
        key_temp[key_index] = key_byte
        diff = mix_col(plain, key_temp)[diff0_index]
        difftag = mix_col(plaintag, key_temp)[diff0_index]
        kbytediff[diff ^ difftag].append(key_byte)
    key_triple =  defaultdict(list)
    for diff in k0k5diff.keys():
        if diff in kbytediff.keys():
            for k0, k5 in k0k5diff[diff]:
                kbyte = kbytediff[diff]
                key_triple[k0+k5*256] = key_triple[k0+k5*256] + kbyte
                if k0 == k0real and False:
                    print ('This is the real deal', k0, k5, key_triple[k0+k5*256])
    return key_triple


def get_plain_of_cipher_mix(pi, ptagi):
    ci = aes.encrypt(pi)
    ctagi = aes.encrypt(ptagi)
    c2i, c2tagi = get_mixture(ci, ctagi)
    p2i = aes.decrypt(c2i)
    p2tagi = aes.decrypt(c2tagi)
    return p2i, p2tagi


def find_key(pi, ptagi, p2i10, p2tagi10, p2i15, p2tagi15, index10, index15, diff0_index, col):
    triple10 = MiTM(p2i10, p2tagi10, key_pairs_vec[diff0_index], 3, diff0_index)
    triple15 = MiTM(p2i15, p2tagi15, key_pairs_vec[diff0_index], 2, diff0_index)
    cipher_pair_for_check = []
    for i in range(256):
        if i == index10 or i == index15:
            continue
        pi[1] = i
        ptagi[1] = i
        p2i, p2tagi = get_plain_of_cipher_mix(pi, ptagi)
        cipher_pair_for_check.append([get_col(p2i,col), get_col(p2tagi, col)])
        if len(cipher_pair_for_check) >= num_cipher_for_check:
            break
    calc_keys = []
    cnt = 0
    for k0k5 in triple10.keys():
        if k0k5 in triple15.keys():
            k0 = k0k5 % 256
            k5 = k0k5 // 256
            if True:
                for k10 in triple15[k0k5]:
                    for k15 in triple10[k0k5]:
                        if k0 == k0real and False:
                            print ([k0, k5, k10, k15])
                            print ([k0 ^ p_5 ^ p_5_tag, k5, k10, k15])
                        cnt += 1
                        for i in range(num_cipher_for_check):
                            p2col, p2tagcol = cipher_pair_for_check[i]
                            diff = mix_col(p2col, [k0, k5, k10, k15])[diff0_index]
                            difftag = mix_col(p2tagcol, [k0, k5, k10, k15])[diff0_index]
                            if diff != difftag:
                                break
                        if diff == difftag:
                            print ('Recovered key is', [k0, k5, k10, k15])
                            calc_keys.append([k0, k5, k10, k15])
    return calc_keys


def get_key_suggestion(cur_pair, col=0):
    pi = cur_pair[0][:]
    ptagi = cur_pair[1][:]
    p2i10 = None
    p2i15 = None
    for i in range(256):
        pi[1] = i
        ptagi[1] = i
        p2i, p2tagi = get_plain_of_cipher_mix(pi, ptagi)

        if p2tagi[10] ^ p2i[10] == 0 and p2i10 is None:
            if verbose:
                p2i1 = mixcol_first_round(p2i, keyarr,0)
                p2tagi1 = mixcol_first_round(p2tagi, keyarr, 0)
                pi1 = mixcol_first_round(pi, keyarr, 0)
                ptagi1 = mixcol_first_round(ptagi, keyarr, 0)
                print ('one round diff 10', p2i1^p2tagi1, pi1^ptagi1)
                print ('plain ', get_col(p2i, col), get_col(p2tagi, col))
            p2i10 = p2i
            p2tagi10 = p2tagi
            index10 = i

        if p2tagi[15] ^ p2i[15] == 0 and p2i15 is None:
            if verbose:
                p2i1 = mixcol_first_round(p2i, keyarr,0)
                p2tagi1 = mixcol_first_round(p2tagi, keyarr, 0)
                pi1 = mixcol_first_round(pi, keyarr, 0)
                ptagi1 = mixcol_first_round(ptagi, keyarr, 0)
                print ('one round diff 15', p2i1^p2tagi1, pi1^ptagi1)
                print ('plain ', get_col(p2i, col), get_col(p2tagi, col))
            p2i15 = p2i
            p2tagi15 = p2tagi
            index15 = i

        if (p2i10 is not None) and (p2i15 is not None):
            for index in range(4):
                calc_keys = find_key(pi, ptagi, p2i10, p2tagi10, p2i15, p2tagi15, index10, index15, index, col)
                if len(calc_keys) > 0:
                    return calc_keys
            return None





#prepare possible plaintext pairs
plain_text = [0] * 16

p_5 = 0
p_5_tag = 1
p = plain_text[:]
p[5] = p_5
p_tag = plain_text[:]
p_tag[5] = p_5_tag
if struct_pairs:
    pairs = []
    for i in range(16):
        for j in range(16, 16+8):
            pairs.append([[i] + p[1:], [j] + p_tag[1:]])
else:
    pairs = [[p, [val] + p_tag[1:]] for val in range(1,129)]

#prepare possible diff to k5
diff2k5 = calc_key_from_diff(p_5,p_5_tag)

total_run = 0
total_key_find = 0
total_key_find_good = 0
pair_found = []
for key_index in range(len(key)):
#for key_index in range(1, 4):
    keyarr = bytes_from_hex(key[key_index])
    aes = AESr(keyarr, 5)
    k5 = keyarr[5]
    k0real = keyarr[0]
    k15 = keyarr[15]
    k10 = keyarr[10]
    key_pairs_vec = [[]]*4

    print ('starting attack on key number', key_index, ' with pair', end=' ')
    print ('len pairs ', len(pairs))
    #iterating on up to 7 bits of pairs
    for pair_index in range(len(pairs)):
        print (pair_index, end=' ')
        cur_pair = pairs[pair_index]
        p0 = cur_pair[0][0]
        ptag0 = cur_pair[1][0]
        #negligble pre process work to generate 4 possible k0 k5 pairs
        for i in range(4):
            key_pairs_vec[i] = get_key_pairs(p0, ptag0, i)

        #up to 8 bit of 2 encryptions and 2 decryptions
        #then 2 MiTM attacks negligble work as uses only single col one round encryptions
        #calc_key = get_key_suggestion(pairs[pair_index], diff0_index)
        calc_key = get_key_suggestion(pairs[pair_index])
        if calc_key is not None:
            break
    print ('\nreal key number', key_index, [k0real, k5, k10, k15])
    print ('calc key', calc_key, ' from pair index ', pair_index)
    total_run += 1
    if calc_key is not None:
        total_key_find += 1
        good_key = calc_key[0] == [k0real, k5, k10, k15]
        print ('good key? ', good_key)
        if good_key:
            total_key_find_good += 1
            pair_found.append(pair_index)
    print ('found good', total_key_find_good, ' out of found ', total_key_find, ' out of', total_run)
pair_found.sort()
pair_found = np.array(pair_found)
prob = np.zeros(len(pairs))
for i in range(len(pairs)):
    prob[i] = sum(pair_found <= i)
prob = prob  * 1.0 / total_run

if struct_pairs:
    filename = 'RB%dStruct.pickle' % len(key)
else:
    filename = 'RB%d.pickle' % len(key)
print('Filename is ', filename)
with open(filename, 'wb') as handle:
    pickle.dump([pairs, pair_found, total_key_find_good], handle)

plt.plot(range(len(pairs)), prob)
plt.show()
