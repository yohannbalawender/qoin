import ecdsa
import base64
import os

class User:
    def __init__(self, name, email, priv = None, pub = None):
        self.name = name
        self.email = email
        if priv == None and pub == None:
            sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
            self.private_key = sk.to_string()
            self.public_key  = sk.get_verifying_key().to_string()
        else:
            self.private_key = priv
            self.public_key  = pub

    def serialize(self):
        return {
            'name': self.name,
            'email': self.email,
            'private_key': base64.b64encode(self.private_key),
            'public_key': base64.b64encode(self.public_key),
        }
    def __str__(self):
        return 'User: %s [%s]\n      pubKey:%s\n      privKey:#######' %\
                (self.email, self.name, base64.b64encode(self.public_key))

