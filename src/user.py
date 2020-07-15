import ecdsa
import base64
import hashlib

import random
import string
import time

import logging

logger = logging.getLogger('blockchain')
hdlr = logging.FileHandler('log/blockchain.log')

formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr)

# Number of allowed per minute
ALLOWED_TRANSACTION_PER_MIN = 5


class AuthenticationError(Exception):
    """Basic exception class for authentication error"""
    pass


def random_string(length):
    """ Generate random string from ASCII table """
    letters = string.ascii_letters
    return ''.join(random.choice(letters) for i in range(length))


def random_hex(length):
    """ Generate random string from HEX digits """
    return ''.join(random.choice(string.hexdigits) for i in range(length))


class User:
    def __init__(self, name, email, passwd,
                 priv=None, pub=None,
                 salt='', services=[], tx_list=[],
                 admin=False):
        self.name = name
        self.email = email
        self.passwd = passwd
        self.salt = salt
        self.services = services
        self.tx_list = []
        self.admin = admin

        if priv is None and pub is None:
            sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
            self.private_key = sk.to_string()
            self.public_key = sk.get_verifying_key().to_string()
        else:
            self.private_key = priv
            self.public_key = pub

    def serialize(self):
        return {
            'name': self.name,
            'email': self.email,
            'passwd': self.passwd,
            'private_key': base64.b64encode(self.private_key),
            'public_key': base64.b64encode(self.public_key),
            'salt': self.salt,
            'services': self.services,
            'tx_list': self.tx_list,
            'admin': self.admin
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

    def add_user_service(self, service):
        # Only one service for the time being
        self.services = [service]

    def declare_service(self, role):
        key = random_hex(32)
        service = {'key': key, 'role': role}

        self.add_user_service(service)

        return service

    def check_service_key(self, service):
        found = False

        for s in self.services:
            # Check same role
            if s['role'] != service[2]:
                continue

            if s['key'] == service[4]:
                found = True
                break

        return found and service[3] == self.email

    def push_tx(self, tx):
        if len(self.tx_list) == ALLOWED_TRANSACTION_PER_MIN:
            self.tx_list.pop(0)

        self.tx_list.append(tx.ts)

    def has_allowed_transaction(self):
        if self.admin:
            return True

        return len(self.tx_list) < ALLOWED_TRANSACTION_PER_MIN \
            or time.time() - self.tx_list[0] > 60

    def __str__(self):
        return 'User: %s [%s]\n      pubKey:%s\n      privKey:#######' %\
                (self.email, self.name, base64.b64encode(self.public_key))

