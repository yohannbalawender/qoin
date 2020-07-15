import ecdsa
import base64
import os
import hashlib
import time

import logging

logger = logging.getLogger('blockchain')
hdlr = logging.FileHandler('log/blockchain.log')

formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr)

class User:
    def __init__(self, name, email, passwd, priv = None, pub = None):
        self.name = name
        self.email = email
        self.passwd = passwd
        self.token = None

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
            'passwd': self.passwd,
            'private_key': base64.b64encode(self.private_key),
            'public_key': base64.b64encode(self.public_key),
        }

    def authenticate(self, _passwd):
        hash_passwd = hashlib.sha256(_passwd.encode('utf-8')).hexdigest()

        return self.passwd == hash_passwd

    def __str__(self):
        return 'User: %s [%s]\n      pubKey:%s\n      privKey:#######' %\
                (self.email, self.name, base64.b64encode(self.public_key))

