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

# This file generates the graph of the success probability of the attack 
# as described in the paper "The Retracing Boomerang Attack" in the section "Experimental verification"

import pickle
import matplotlib.pyplot as plt
import numpy as np

from math import log
from keys500 import key
total_run = len(key)
with open('RB500.pickle', 'rb') as handle:
    [pairs, pair_found, total_key_find_good] = pickle.load(handle)


prob = np.zeros(len(pairs))
for i in range(len(pairs)):
    prob[i] = sum(pair_found <= i)
prob1 = prob  * 1.0 / total_run
num_pairs1 = range(1,len(pairs)+1)

with open('RB500Struct.pickle', 'rb') as handle:
    [pairs, pair_found, total_key_find_good] = pickle.load(handle)



prob = np.zeros(len(pairs))
for i in range(len(pairs)):
    prob[i] = sum(pair_found <= i)
prob2 = prob  * 1.0 / total_run
num_pairs2 = range(1,len(pairs)+1)

w, h = plt.figaspect(0.5)
plt.figure(figsize=(w, h))
plt.plot(num_pairs1, prob1, 'b-', label='i.i.d pairs')
plt.plot(num_pairs2, prob2, 'r--', label='structured pairs')
plt.legend(loc='upper left')
plt.ylabel('Attack Success Probability')
plt.xlabel('Number of Plaintext Pairs')
plt.savefig('RB.png', dpi=600, format='png')
plt.show()


