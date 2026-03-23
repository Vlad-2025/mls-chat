import os, json
from mimetypes import inited

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
        self.nodes = [Node() for _ in range(2 * n - 1)]

    def leaf(self, member_idx):
        return (self.n - 1) + member_idx

    def parent(self, i):
        return None if i == 0 else (i - 1) // 2

    def left(self, i):
        return 2 * i + 1

    def right(self, i):
        return 2 * i + 2

    def is_leaf(self, i):
        return i >= self.n - 1

    def sibling(self, i):
        if i == 0:
            return None

        p = self.parent(i)

        # return the child of the parent of i that isnt 'i' (so if 'i' was left, it return right(p))
        return self.right(p) if self.left(p) == i else self.left(p)

    def leaves_in_subtree(self, i):
        """All leaf indices inside subtree at i"""
        if self.is_leaf(i):
            return [i]

        return self.leaves_in_subtree(self.left(i)) + self.leaves_in_subtree(self.right(i))

    def derive_parent(self, l, r):
        """
        parent_secret = HKDF(ECDH(priv_left, pub_right))
        l, r are node indices — we look up the nodes internally.
        """
        ln, rn = self.nodes[l], self.nodes[r]

        if ln.priv and rn.pub:
            raw = ln.priv.exchange(rn.pub)

        elif rn.priv and ln.pub:
            raw = rn.priv.exchange(ln.pub)

        else:
            return None  # in order to handle blank subtrees

        return hkdf(raw, info=b'parent')

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

        # treat nodes with no key material as blank — they are unreachable
        if nd.blank or nd.pub is None:
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
        for ks, ph in snap.items():
            i = int(ks)
            self.nodes[i].set_pub(pub_from_bytes(bytes.fromhex(ph)))

    def blank_path(self, member_idx):

        i = self.leaf(member_idx)

        self.nodes[i].clear()

        while True:
            p = self.parent(i)

            if p is None:
                break

            self.nodes[p].clear()

            i = p


'''

a node can be in three states:
- you own it    : you know the secret, you can derive the keypair, you have both priv and pub
- you know of it: you receive someone else's public key and only that
- it's blank    : a member was removed from this slot and it's empty, no keys

'''


class Node:
    def __init__(self):
        self.secret = None  # 32 random bytes
        self.priv = None  # derived from secret deterministically
        self.pub = None  # derived from private
        self.blank = False  # True when member was removed

    def set_secret(self, s):
        self.secret = s
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


class Member:
    def __init__(self, name, idx, n=4):
        self.name = name
        self.idx = idx
        self.tree = Tree(n)
        self.root = None

        # long-term identity keypair, used for 'Welcome' encryption
        self.id_priv, self.id_pub = generate_keypair()

    @property
    # leaf index -> helper function
    def li(self):
        return self.tree.leaf(self.idx)

    def init_leaf(self):
        self.tree.nodes[self.li].set_secret(os.urandom(32))

    # The commit builder

    def commit(self, forced=None):

        forced = forced or {}

        # 1) fresh leaf
        self.init_leaf()

        entries = []
        i = self.li

        while True:
            p = self.tree.parent(i)

            if p is None:
                break

            l, r = self.tree.left(p), self.tree.right(p)
            sib = self.tree.sibling(i)  # the subtree we need to send the secret to

            # 2) derive the parent secret
            if p in forced:
                p_secret = forced[p]

                self.tree.nodes[p].set_secret(p_secret)

            else:
                p_secret = self.tree.derive_parent(l, r)

                if p_secret is None:
                    # sibling subtree has no key material (sparse tree) —
                    # treat like a forced secret and cover our own side too
                    p_secret = os.urandom(32)
                    forced[p] = p_secret  # mark so own-side broadcast fires below

                self.tree.nodes[p].set_secret(p_secret)

            # 3) encrypt to sibling resolution
            sib_res = self.tree.resolution(sib)

            for rn in sib_res:
                pub = self.tree.nodes[rn].pub
                pkg = ecdh_encrypt(p_secret, pub)

                entries.append({
                    "recipient": rn,  # node index, who can decrypt this
                    "level": p,  # which tree nodes this secret belongs to
                    "pkg": pkg
                })
                '''
                Each entry in the commit says: "node 'rn' can decrypt this and needs to store
                it as the secret for node 'p'"
                '''

            if p in forced:
                our_side = [x for x in self.tree.leaves_in_subtree(i)
                            if x != self.li
                            and not self.tree.nodes[x].blank
                            and self.tree.nodes[x].pub is not None]
                for rn in our_side:
                    entries.append({
                        "recipient": rn,
                        "level": p,
                        "pkg": ecdh_encrypt(p_secret, self.tree.nodes[rn].pub)
                    })
                '''
                When this parent's secret was forced (couldnt derive via ECDH because the
                sibling subtree was blank), members on our side of the tree also cannot derive
                this secret by going up -> they will hit the blank node too

                -> encrypt this secret directly to each surviving leaf on our side 
                (all in the subtree except us)
                '''

            # move up the path
            i = p

        self.root = self.tree.nodes[0].secret

        return {
            "from": self.idx,
            "leaf_pub": pub_bytes(self.tree.nodes[self.li].pub).hex(),
            "entries": entries,
            "snap": self.tree.snapshot()
        }

    def recv(self, c, removed_idx=None):
        # If this is a remove commit, blank the removed member first
        if removed_idx is not None:
            self.tree.blank_path(removed_idx)

        # Update commmiter's new leaf pub
        cl = self.tree.leaf(c["from"])
        if cl != self.li:
            self.tree.nodes[cl].set_pub(pub_from_bytes(bytes.fromhex(c["leaf_pub"])))

        # Refresh all PUBLIC keys from the snapshot
        self.tree.apply_snap(c["snap"])

        # Find the one we can decrypt
        for entry in sorted(c["entries"], key=lambda e: e["level"]):
            rn = entry["recipient"]
            nd = self.tree.nodes[rn]

            if nd.priv is None:
                continue  # not ours

            p_secret = ecdh_decrypt(entry["pkg"], nd.priv)
            level_node = entry["level"]
            self.tree.nodes[level_node].set_secret(p_secret)

            # Derive upward from form level_node to root:
            j = level_node
            while True:
                pp = self.tree.parent(j)
                if pp is None:
                    break

                s = self.tree.derive_parent(self.tree.left(pp), self.tree.right(pp))
                if s is None:
                    break

                self.tree.nodes[pp].set_secret(s)

                # move up the tree
                j = pp

            self.root = self.tree.nodes[0].secret
            return  # one entry is all we need

        raise RuntimeError(f"[{self.name}] nothing to decrypt in commit")

    def remove(self, removed_idx):
        self.tree.blank_path(removed_idx)

        # pre-scan: find which parents cant be derived on our path
        forced = {}
        i = self.li

        while True:
            p = self.tree.parent(i)
            if p is None:
                break

            l, r = self.tree.left(p), self.tree.right(p)

            if self.tree.derive_parent(l, r) is None:
                forced[p] = os.urandom(32)

            i = p

        return self.commit(forced=forced)

    def add(self, new_idx, new_id_pub):
        new_leaf = self.tree.leaf(new_idx)
        leaf_sec = os.urandom(32)
        self.tree.nodes[new_leaf].set_secret(leaf_sec)

        # Blank parents above new leaf
        j = new_leaf
        while True:
            pp = self.tree.parent(j)
            if pp is None:
                break

            self.tree.nodes[pp].clear()

            j = pp

        # pre-scan again
        forced = {}

        i = self.li

        while True:
            p = self.tree.parent(i)
            if p is None:
                break

            if self.tree.derive_parent(self.tree.left(p), self.tree.right(p)) is None:
                forced[p] = os.urandom(32)

            i = p

        c = self.commit(forced=forced)

        payload = json.dumps({
            "idx": new_idx,
            "lsec": leaf_sec.hex(),
            "root": self.root.hex(),
            "snap": c["snap"]
        }).encode()

        welcome = {
            "pkg": ecdh_encrypt(payload, new_id_pub)
        }

        return c, welcome

    @classmethod
    def from_welcome(cls, name, idx, id_priv, welcome, n=4):
        pl = json.loads(ecdh_decrypt(welcome["pkg"], id_priv))
        m = cls(name, idx, n)
        m.id_priv = id_priv
        m.id_pub = id_priv.public_key()
        m.tree.nodes[m.li].set_secret(bytes.fromhex(pl["lsec"]))
        m.tree.apply_snap(pl["snap"])
        m.root = bytes.fromhex(pl["root"])
        m.tree.nodes[0].set_secret(m.root)
        print(f"[{name}] joined, root = {m.root.hex()[:20]}...")
        return m

    # In case you just want to update the key
    def key_update(self):
        return self.commit()


# Crypto

def hkdf(ikm, info=b'treekem', length=32):
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


def generate_keypair():
    priv = X25519PrivateKey.generate()
    return priv, priv.public_key()


def pub_bytes(pub):
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def pub_from_bytes(b):
    return X25519PublicKey.from_public_bytes(b)


def ecdh_encrypt(plaintext, recipient_pub):
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