import os, json
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

'''

        0
       / \
      1   2
     / \ / \
    3  4 5  6

'''

'''

n = 4 (number of leaves)

Indexes:
    parent of i         : (i-1)//2
    left child of i     : 2i + 1
    right child of i    : 2i + 2
    leaves start at     : n - 1
    
'''

class Tree:
    def __init__(self, n=4):
        self.n = n
        self.nodes = [None] * (2*n - 1)

    def leaf(self, member_idx):
        return (self.n - 1) + member_idx

    def parent(self, i):
        return None if i == 0 else (i - 1)//2

    def left(self, i):
        return 2*i + 1

    def right(self, i):
        return 2*i + 2

    def is_leaf(self, i):
        return i >= self.n-1

    def sibling(self, i):
        if i == 0:
            return None

        p = self.parent(i)

        # return the child of the parent of i that isnt 'i' (so if 'i' was left, it return right(p))
        return self.right(p) if self.left(p) == i else self.left(p)