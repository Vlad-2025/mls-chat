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
        self.nodes = [Node() for _ in range(2*n - 1)]

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

    '''
    Resolution:

    Whenever someone (a node) wants to send a secret to everyone in a subtree, there might be gaps
    in it (blank nodes) -> you can't encrpyt the substree root if its blank, so you need to find the
    reachable members

    the resolution of the subtree ->    a set of the highest non-blank nodes that together cover all
                                        surviving members of that tree
                                        
    For a complete tree with no removals, resolution(2) on the CD subtree returns [2], just the CD
    parent node, because it's not blank and covers C and D
    
    After D is removed, resolution(2) returns [5] -> just C's leaf because node 2 is now blank and
    D's leaf is blank, so we only return C                                  
    
    '''

    def resolution(self, i):
        nd = self.nodes[i]

        if nd.blank:
            if self.is_leaf(i):
                return []

            return (
                    self.resolution(self.left(i)) +
                    self.resolution(self.right(i))
                    )

        return [i]


    '''
    The snapshot mechanism:
    
    A tree node needs to shareable across members
    The snapshot is a dict of {node_index: public_key_hex} for every node with a public key
    
    '''
    def snapshot(self):
        return {
            i: pub_bytes(node.pub).hex() for i, node in enumerate(self.nodes) if node.pub
        }

    def apply_snap(self, snap):
        for ks, ph in snap.items:
            i = int(ks)
            self.nodes[i].set_pub(pub_from_bytes(bytes.fromhex(ph)))

'''

a node can be in three states:
- you own it    : you know the secret, you can derive the keypair, you have both priv and pub
- you know of it: you receive someone else's public key and only that
- it's blank    : a member was removed from this slot and it's empty, no keys

'''

class Node:
    def __init__(self):
        self.secret = None  # 32 random bytes
        self.priv   = None  # derived from secret deterministically
        self.pub    = None  # derived from private
        self.blank  = False # True when member was removed

    def set_secret(self, s):
        self.secret = 0
        self.priv, self.pub = keypair_from_secret(s)
        self.blank = False

    def set_pub(self, pub):
        if self.priv is None:
            self.secret = None

        self.pub = pub
        self.blank = False

    def clear(self):
        self.secret = self.priv = self.pub = None
        self.blank = True


# Crypto

def hkdf(ikm, info=b'treekem', length = 32):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info
    ).derive(ikm)


def keypair_from_secret(secret):
    """
    returns (priv_key, pub_key) based on 'secret' parameter
    """
    kb = hkdf(secret, info=b'keypair')
    priv = X25519PrivateKey.from_private_bytes(kb)

    return priv, priv.public_key()

def pub_bytes(pub):
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

def pub_from_bytes(b):
    return X25519PublicKey.from_public_bytes(b)

def derive_parent(ln:Node, rn:Node):
    """
    parent_secret = HKDF(ECDH(priv_left, pub_right))
    works based on which side has the private key (it's symmetric)
    -> each node can compute the parent secret independently
    """
    if ln.priv and rn.pub:
        raw = ln.priv.exchange(rn.pub)

    elif rn.priv and ln.pub:
        raw = rn.priv.exchange(ln.pub)

    else:
        return None # in order to handle blank subtrees

    return hkdf(raw, info=b'parent')

def ecdh_encrpyt(plaintext, recipient_pub):
    eph_priv = X25519PrivateKey.generate()
    eph_pub = eph_priv.public_key()

    shared = eph_priv.exchange(recipient_pub)

    key = hkdf(shared, b'ecdh-enc')

    nonce = os.urandom(12)

    ct = AESGCM(key).encrypt(nonce, plaintext, None)

    return {
        "e": pub_bytes(eph_pub).hex(),
        "n": nonce.hex(),
        "c": ct.hex()
    }

def ecdh_decrypt(pkg, priv):
    epub = pub_from_bytes(bytes.fromhex(pkg["e"]))
    key = hkdf(priv.exchange(epub), info=b"ecdh-enc")

    return AESGCM(key).decrypt(
        bytes.fromhex(pkg["n"]),
        bytes.fromhex(pkg["c"]),
        None
    )

