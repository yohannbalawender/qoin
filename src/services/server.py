#!/usr/bin/python

import os
import socket
import signal
import sys
import stat
import json
import base64
import time
from argparse import ArgumentParser
import hashlib

import rpyc
from cryptography.fernet import Fernet

from src.utils import load_configuration_file, get_logger_by_name
from src.services.node import Leader
from src.blockchain import Block, Transaction
from src.users import User

# MASTER_IDENTIFIER = 'blockchain-master'
MASTER_IDENTIFIER = 'master@intersec.com'
SECRET_KEY = None
DEFAULT_EXPIRY = 86400 * 90

# Logger {{{

logger = get_logger_by_name('Blockchain server')

# }}}


class BlockChainServer(Leader):
    node_name = "Blockchain server"
    BLOCK_CHAIN = []

    def _add_block(self, block):
        self.BLOCK_CHAIN.append(block)

    def _load_block(self, s_block, prev_hash):
        def _add_transaction_list(s_block):
            tx_list = []

            for s_tx in s_block['tx_list']:
                tx = Transaction(None, None, s_tx['amount'], s_tx['ts'])
                tx.snd = base64.b64decode(s_tx['snd'])
                tx.rcv = base64.b64decode(s_tx['rcv'])
                tx.signature = base64.b64decode(s_tx['signature'])
                tx_list.append(tx)

            return tx_list

        block = Block(None, None, None, None)

        block.index = s_block['index']
        block.ts = s_block['ts']
        block.prev_hash = s_block['prev_hash']
        block.tx_list = _add_transaction_list(s_block)
        block.nonce = s_block['nonce']
        block.hash = s_block['hash']

        # Block validity
        if not block.check_validity():
            raise BaseException('Cannot restore the blockchain because a '
                                'signature is invalid')

        # Blockchain integrity
        if s_block['index'] > 0:
            if s_block['prev_hash'] != prev_hash:
                raise BaseException('Cannot restore the blockchain because '
                                    'hash is invalid')

        print block
        self.BLOCK_CHAIN.append(block)

        return s_block['hash']

    def _restore_blockchain_from_json(self, s_blocks):
        """
            Restore the blockchain from a serialized source
        """
        prev_hash = None

        for data in s_blocks:
            prev_hash = self._load_block(data, prev_hash)

    def load_blockchain(self, conf):
        """
            Open the blockchain file and restore the blockchain
        """
        filepath = conf['blockchainDir'] + '/dump.json'
        if not os.path.isfile(filepath):
            return

        with open(filepath) as json_file:
            data = json.load(json_file)
            self._restore_blockchain_from_json(data)

        self.service.initialize()

    def save_blockchain(self, conf):
        def set_internal_dir(path):
            os.mkdir(path)
            # Read and execute owner permission
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

        def set_internal_file_mod(path):
            # Read and write owner permission
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)

        dir_path = conf['blockchainDir']
        if not os.path.exists(dir_path):
            set_internal_dir(dir_path)

        blocks = []
        for block in self.BLOCK_CHAIN:
            blocks.append(block.serialize())

        file_path = conf['blockchainDir'] + '/dump.json'
        with open(file_path, 'w') as outfile:
            json.dump(blocks, outfile)
            set_internal_file_mod(file_path)


class BlockChainService(rpyc.Service):
    # Shared instance with the server
    BLOCK_CHAIN = []

    USERS = {}

    def initialize(self):
        if MASTER_IDENTIFIER not in self.USERS:
            self._create_master_user()

        if len(self.BLOCK_CHAIN) == 0:
            self.BLOCK_CHAIN.append(self._create_genesis_block())

    def _create_master_user(self):
        sha_passwd = hashlib.sha256()

        self.USERS[MASTER_IDENTIFIER] = User('master', MASTER_IDENTIFIER,
                                             sha_passwd.hexdigest(),
                                             admin=True)

    def _create_genesis_block(self):
        master_user = self.USERS[MASTER_IDENTIFIER]
        tx = Transaction(master_user,
                         master_user,
                         conf['defaultGenesisAmount'], time.time())
        block = Block(0, time.time(), None, [tx])
        nonce, hash = block.gen_hash()
        block.set_hash(nonce, hash)
        return block

    def set_blockchain(self, BLOCK_CHAIN):
        """
            Store the blockchain reference
        """

        self.BLOCK_CHAIN = BLOCK_CHAIN

    # Transaction {{{

    # def handle_transaction(self, author, recipient, amount):
    #     if recipient not in self.USERS:
    #         return {'code': 400, 'message': 'Unknown user'}

    #     if get_account_history(author)['balance'] < amount:
    #         return {'code': 400, 'message': 'Unsufficient balance'}

    #     res = self.send_coin(USERS[author], USERS[recipient], amount)

    #     if res:
    #         return {'code': 200,
    #                 'message': 'Transaction will be added to block'}
    #     else:
    #         return {'code': 400,
    #                 'message': 'Unable to process the transaction'}

    # }}}
    # Users {{{

    def _authenticate_master(self, priv):
        if priv != self.USERS[MASTER_IDENTIFIER].private_key:
            return False, 'Authentication failed', 400

        return True

    def is_user_authenticated(self, token):
        global SECRET_KEY

        cipher = Fernet(SECRET_KEY)
        ts = cipher.extract_timestamp(token)
        now = int(time.time())

        if (now - ts) > DEFAULT_EXPIRY:
            return False, 'Authentication expired', 400

        b64 = cipher.decrypt(token)
        plain = base64.b64decode(b64)
        _json = json.loads(plain)

        user = self.USERS[_json['email']]

        if user is None:
            return False, 'Unknown session', 400

        if user.is_authenticated(_json['token']):
            return user
        else:
            return False, 'Fail to authenticate', 400

    def _create_user(self, name, email, passwd, admin):
        if email not in self.USERS:
            sha_passwd = hashlib.sha256()
            sha_passwd.update(passwd.encode('utf-8'))
            user = User(name, email, sha_passwd.hexdigest(), admin=admin)
            self.USERS[email] = user

            return True

        return False

    def exposed_master_create_user(self, priv, **kwargs):
        res, err, code = self._authenticate_master(priv)

        if not res:
            return {'message': err}, code

        if self._create_user(**kwargs):
            return {'message': 'User successfully created'}, 200
        else:
            return {'message': 'Failed to create the user'}, 400

    def exposed_declare_service(self, token, role):
        res, err, code = self.is_user_authenticated(token)

        if not res:
            return {'message': err}, code

        user = res

        service = user.declare_service(role)

        return {'message': 'Service declared successfully',
                'serviceKey':  service['key']}, 200

    def exposed_list_users(self, token):
        res, err, code = self.is_user_authenticated(token)

        if not res:
            return {'message': err}, code

        user = res

        users = [{'name': self.USERS[k].name, 'email': self.USERS[k].email}
                 for k in self.USERS if self.USERS[k].email != user.email]

        return {'users': users}, 200

    def exposed_service_refresh_key(self, token, key):
        res, err, code = self.is_user_authenticated(token)

        if not res:
            return {'message': err}, code

        user = res

        new_key, err = user.service_refresh_key(key)

        if err:
            return {'message': 'Could not change the service key'}, 400

        return {'key': new_key}, 200

    # }}}


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('-c', '--conf',
                        help='server configuration file')

    args = parser.parse_args()
    conf = load_configuration_file(args.conf)

    try:
        hostname = conf['hostname']
    except KeyError:
        hostname = socket.gethostname()

    server = BlockChainServer(BlockChainService(),
                              hostname=hostname, port=conf['port'],
                              protocol_config={"allow_public_attrs": True,
                                               "allow_pickle": True})

    server.load_blockchain(conf)

    def signal_handler(sig, frame):
        server.save_blockchain(conf)
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    logger.info('Server up and running')

    server.start()
