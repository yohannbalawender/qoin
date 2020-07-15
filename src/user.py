import ecdsa
import base64
import os
import hashlib
import time

import random
import string

import logging

logger = logging.getLogger('blockchain')
hdlr = logging.FileHandler('log/blockchain.log')

formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr)

class AuthenticationError(Exception):
    """Basic exception class for authentication error"""
    pass

def random_string(length):
    """ Generate random string from ASCII table """
    letters = string.ascii_letters
    return ''.join(random.choice(letters) for i in range(length))

class User:
    def __init__(self, name, email, passwd,
                 priv = None, pub = None,
                 salt = ''):
        self.name = name
        self.email = email
        self.passwd = passwd
        self.salt = salt

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
            'salt': self.salt,
        }

    def _get_hash(self, to_hash):
        sha = hashlib.sha256()
        sha.update(to_hash.encode('utf-8'))

        return sha.hexdigest()

    def _generate_token(self):
        self.salt = random_string(16)
        to_hash = '%s%s' % (self.salt, self.passwd)

        return self._get_hash(to_hash)

    def _check_token(self, token):
        to_hash = '%s%s' % (self.salt, self.passwd)

        user_token = self._get_hash(to_hash)

        return user_token == token

    def authenticate(self, _passwd):
        hash_passwd = hashlib.sha256()
        hash_passwd.update(_passwd.encode('utf-8'))
        sha_passwd = hash_passwd.hexdigest()

        if sha_passwd != self.passwd:
            raise AuthenticationError('Bad password')

        return self._generate_token()

    def is_authenticated(self, token):
        return self._check_token(token)

    def __str__(self):
        return 'User: %s [%s]\n      pubKey:%s\n      privKey:#######' %\
                (self.email, self.name, base64.b64encode(self.public_key))

