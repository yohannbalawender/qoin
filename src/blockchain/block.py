#!/usr/bin/python

import hashlib
import ecdsa

DIFFICULTY = 1


def has_proof_of_work(hash):
    # Number of most significant bytes that are zero.
    return int(hash[:DIFFICULTY], 16) == 0


def hash_block(_str):
    sha = hashlib.sha256()
    sha.update(_str.encode('utf-8'))
    return sha.hexdigest()


class Block:
    def __init__(self, index, ts, prev_hash, tx_list):
        self.index = index
        self.ts = ts
        self.prev_hash = prev_hash if prev_hash is not None else ''
        self.tx_list = tx_list
        self.nonce = None
        self.hash = None

    def __str__(self):
        _str = 'block: #%d : ts:%d\n' % (self.index, self.ts)
        _str += '       prevHash:%s... hash:%s...\n' % (self.prev_hash[:5],
                                                        self.hash[:5])
        _str += '       nonce:%s\n' % (self.nonce)
        for tx in self.tx_list:
            _str += str(tx)
        return _str

    def serialize(self):
        tx_list = [tx.serialize() for tx in self.tx_list]
        return {
            'index': self.index,
            'ts': self.ts,
            'prev_hash': self.prev_hash,
            'nonce': self.nonce,
            'hash': self.hash,
            'tx_list': tx_list
        }

    def check_hash_validity(self, nonce, hash):
        tx_list_hash = ''
        for tx in self.tx_list:
            tx_list_hash += tx.hash_format()

        to_hash = '%d%d%d%s%s' % (self.index, nonce, self.ts, self.prev_hash,
                                  tx_list_hash)

        return hash_block(to_hash) == hash

    def check_validity(self):
        valid = True

        for tx in self.tx_list:
            vk_str = tx.snd
            vk = ecdsa.VerifyingKey.from_string(vk_str, curve=ecdsa.SECP256k1)

            msg = '%d%s%s%d' % (tx.amount,
                                tx.snd,
                                tx.rcv,
                                tx.ts)

            valid = valid and vk.verify(tx.signature,
                                        msg)

        return valid

    def set_hash(self, nonce, hash):
        self.nonce = nonce
        self.hash = hash

    def gen_hash(self):
        nonce = 0
        tx_list_hash = ''
        for tx in self.tx_list:
            tx_list_hash += tx.hash_format()

        while True:
            to_hash = '%d%d%d%s%s' % (self.index, nonce,
                                      self.ts, self.prev_hash,
                                      tx_list_hash)
            hash = hash_block(to_hash)
            if has_proof_of_work(hash):
                return nonce, hash
            nonce += 1

        return None, None
