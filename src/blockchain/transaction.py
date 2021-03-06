#!/usr/bin/python

import ecdsa
import base64
import time


class Transaction:
    def __init__(self, sender=None, receiver=None, amount=0, ts=time.time(),
                 label='Transaction'):
        self.amount = amount
        self.ts = ts
        self.snd = None
        self.rcv = None
        self.signature = None
        self.label = label

        if sender is not None and receiver is not None:
            # Generate sign from sender private key
            self.snd = sender.public_key
            self.rcv = receiver.public_key

            to_sign = '%d%s%s%d' % (self.amount, self.snd, self.rcv, self.ts)
            sk = ecdsa.SigningKey.from_string(sender.private_key,
                                              curve=ecdsa.SECP256k1)
            self.signature = sk.sign(to_sign)

    def serialize(self):
        return {
            'amount': self.amount,
            'snd': base64.b64encode(self.snd),
            'rcv': base64.b64encode(self.rcv),
            'ts': self.ts,
            'signature': base64.b64encode(self.signature),
            'label': self.label
        }

    def hash_format(self):
        return '%d%s%s%d%s' % (self.amount, base64.b64encode(self.snd),
                               base64.b64encode(self.rcv), self.ts,
                               base64.b64encode(self.signature))

    def __str__(self):
        _str = 'Tx: ts:%d %d$ from %s... to %s...\n' % \
                (self.ts, self.amount, base64.b64encode(self.snd)[:5],
                 base64.b64encode(self.rcv)[:5])
        _str += '    sign:%s...' % base64.b64encode(self.signature)[:5]
        return _str
