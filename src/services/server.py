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
from collections import OrderedDict
import threading
from copy import deepcopy

import rpyc
from cryptography.fernet import Fernet

from src.utils import load_configuration_file, get_logger_by_name
from src.services.node import Leader, LeaderService
from src.blockchain import Block, Transaction
from src.users import User, AuthenticationError

MASTER_IDENTIFIER = 'blockchain-master'
SECRET_KEY = None
DEFAULT_EXPIRY = 86400 * 90

# Logger {{{

logger = get_logger_by_name('Blockchain server')

# }}}


class BlockChainServer(Leader):
    """
        Implement the blockchain server
    """
    node_name = "Blockchain server"
    BLOCK_CHAIN = []

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

        logger.info(block)
        self.service.BLOCK_CHAIN.append(block)

        return s_block['hash']

    def load_state(self, conf):
        self.load_users(conf)
        self.load_services(conf)
        self.load_blockchain(conf)

    def restore_users_from_json(self, data):
        for s_user in data:
            user = User(s_user['name'], s_user['email'], s_user['passwd'],
                        priv=base64.b64decode(s_user['private_key']),
                        pub=base64.b64decode(s_user['public_key']),
                        salt=s_user['salt'], services=s_user['services'],
                        tx_list=['tx_list'], admin=s_user['admin'])
            logger.info(user)
            self.service.USERS[user.email] = user
        logger.info('='*20)

    def load_users(self, conf):
        filepath = conf['usersDir'] + '/dump.json'
        if not os.path.isfile(filepath):
            return

        with open(filepath) as json_file:
            data = json.load(json_file)
            self.restore_users_from_json(data)

    def restore_services_from_json(self, data):
        for s_service in data:
            data = (s_service['host'], s_service['port'], s_service['role'])
            s = {'data': data, 'connected': True, 'authenticate': False}

            if 'owner' in s_service and 'key' in s_service['key']:
                s['authenticate'] = {'owner': s_service['owner'],
                                     'key': s_service['key']}

            self.service.SERVICES[s_service['token']] = s

        logger.info('%d services restored' % len(self.service.SERVICES))

    def load_services(self, conf):
        filepath = conf['servicesDir'] + '/dump.json'
        if not os.path.isfile(filepath):
            return

        with open(filepath) as json_file:
            data = json.load(json_file)
            self.restore_services_from_json(data)

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

        self.service.initialize(conf)

    def set_internal_dir(self, path):
        os.mkdir(path)
        # Read and execute owner permission
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

    def set_internal_file_mod(self, path):
        # Read and write owner permission
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)

    def save_state(self, conf):
        self.save_blockchain(conf)
        self.save_users(conf)
        self.save_services(conf)

    def save_blockchain(self, conf):
        """
            Save the blockchain in a JSON file
        """
        dir_path = conf['blockchainDir']
        if not os.path.exists(dir_path):
            self.set_internal_dir(dir_path)

        blocks = []
        for block in self.service.BLOCK_CHAIN:
            blocks.append(block.serialize())

        file_path = conf['blockchainDir'] + '/dump.json'
        with open(file_path, 'w') as outfile:
            json.dump(blocks, outfile)
            self.set_internal_file_mod(file_path)

    def save_users(self, conf):
        """
            Save the users in a JSON file
        """
        dir_path = conf['usersDir']
        if not os.path.exists(dir_path):
            self.set_internal_dir(dir_path)

        service_users = self.service.USERS

        users = [service_users[k].serialize() for k in service_users]

        file_path = conf['usersDir'] + '/dump.json'
        with open(file_path, 'w') as outfile:
            json.dump(users, outfile)
            self.set_internal_file_mod(file_path)

    def save_services(self, conf):
        """
            Save the services state in a JSON file
        """
        dir_path = conf['servicesDir']
        if not os.path.exists(dir_path):
            os.mkdir(dir_path)
            self.set_internal_dir(dir_path)

        services = []

        for k in self.service.SERVICES:
            s = self.service.SERVICES[k]
            data = s['data']
            obj = {'host': data[0], 'port': data[1], 'role': data[2],
                   'token': k}

            if s['authenticate'] is not False:
                auth = s['authenticate']

                obj['owner'] = auth['owner']
                obj['key'] = auth['key']

            services.append(obj)

        file_path = conf['servicesDir'] + '/dump.json'
        with open(file_path, 'w') as outfile:
            json.dump(services, outfile)
            self.set_internal_file_mod(file_path)


class BlockChainService(LeaderService):
    """
        Implement the blockchain service of the server.
        Handle both external interaction and the internal system
    """
    BLOCK_CHAIN = []
    PENDING_BLOCKS = {}

    USERS = {}

    SECRET_KEY = None

    # {{{ Internal

    def initialize(self, conf):
        """
            Initialize the blockchain service and set the needed variables
        """
        if MASTER_IDENTIFIER not in self.USERS:
            self._create_master_user(conf)
            logger.info('Master user created')

        if len(self.BLOCK_CHAIN) == 0:
            self.BLOCK_CHAIN.append(self._create_genesis_block(conf))
            logger.info('Genesis block generated')

        self.SECRET_KEY = conf['secretKey'].encode('ascii')

    def _create_master_user(self, conf):
        master_user = User('master', MASTER_IDENTIFIER,
                           hashlib.sha256().hexdigest(), admin=True)

        self.USERS[MASTER_IDENTIFIER] = master_user

    def _create_genesis_block(self, conf):
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

    def get_user_from_public_key(self, pub):
        """
            Get a user by its public key
        """
        for k in self.USERS:
            if self.USERS[k].public_key == pub:
                return self.USERS[k]
        return None

    def get_account_history(self, email):
        """
            Get the account history by email author
        """
        balance = 0
        history = OrderedDict()
        user = self.USERS[email]

        for block in self.BLOCK_CHAIN:
            for tx in block.tx_list:
                if tx.rcv == user.public_key:
                    balance += tx.amount
                    tx_user = self.get_user_from_public_key(tx.snd)
                    history[tx.ts] = {
                        'amount': tx.amount,
                        'name': tx_user.name,
                        'email': tx_user.email,
                        'label': tx.label
                    }
                elif tx.snd == user.public_key:
                    balance -= tx.amount
                    tx_user = self.get_user_from_public_key(tx.rcv)
                    history[tx.ts] = {
                        'amount': -tx.amount,
                        'name': tx_user.name,
                        'email': tx_user.email,
                        'label': tx.label
                    }

        return {'history': history, 'balance': balance}

    # }}}
    # {{{ Cluster

    def miner_hash_result(self, miner, response):
        s_block = response['result']['block']
        key = (s_block['index'], s_block['ts'], s_block['prev_hash'])
        if key in self.PENDING_BLOCKS:
            pending = self.PENDING_BLOCKS.pop(key, None)

            miner_key = (miner['data'][0], miner['data'][1])
            block = pending[miner_key]

            if not block.check_hash_validity(s_block['nonce'],
                                             s_block['hash']):
                logger.warning('Miner %s sent an invalid hash' %
                               (miner['data'].__str__()))
                self.PENDING_BLOCKS[key] = pending
                return

            # Set hash
            block.set_hash(s_block['nonce'], s_block['hash'])
            logger.info('Solved by miner %s, good job ! ' %
                        (miner['data'].__str__()))
            self.BLOCK_CHAIN.append(block)
        else:
            logger.debug('Bad luck, block already solved')

    def send_miner_compute(self, token, miner, block):
        try:
            conn = rpyc.connect(host=miner['data'][0], port=miner['data'][1])
        except Exception:
            logger.warning('Connection lost with miner %s' %
                           (miner['data'].__str__()))
            key = (block.index, block.ts, block.prev_hash)
            self.PENDING_BLOCKS.pop(key)
            self.forget(token)
            return

        data = block.serialize()

        response = conn.root.compute_hash(data)

        self.miner_hash_result(miner, response)

    def broadcast_miner_compute(self, block):
        cnt = 0
        miners_token = []

        for k in self.SERVICES:
            s = self.SERVICES[k]
            # data[2] is the role of the service
            if s['data'][2] == 'MINER':
                miners_token.append(k)
                cnt += 1

        if cnt == 0:
            logger.error('No miner service available to procede the \
                          transaction. Transaction is lost')
            return False

        pending_block = {}
        self.PENDING_BLOCKS[(block.index, block.ts, block.prev_hash)] = \
            pending_block

        for k in miners_token:
            m = self.SERVICES[k]
            miner_block = deepcopy(block)

            pending_block[(m['data'][0], m['data'][1])] = miner_block

            # Owner and key declared
            if m['authenticate'] is not False:
                try:
                    # Add reward for a user, which has a service declared
                    self.add_reward(m, miner_block)
                except Exception as e:
                    logger.warning('Reward failed: %s' % (e))

            thr = threading.Thread(target=self.send_miner_compute,
                                   args=(k, m, miner_block,))
            thr.start()

        return True

    # }}}
    # Transaction {{{

    def create_transaction(self, sender, receiver, amount,
                           label='Transaction'):
        tx = Transaction(sender, receiver, amount, time.time(), label)

        if sender.has_allowed_transaction():
            sender.push_tx(tx)
            return tx
        else:
            logger.info('Sender %s hits the limit number of allowed '
                        'transaction')
            return False

    def add_reward(self, miner, block):
        """
            Add a reward, if possible, do not stop the transaction
        """
        owner = miner['authenticate']['owner']

        if owner is not None:
            if owner not in self.USERS:
                return

            user = self.USERS[owner]

            if not user.check_service_key(miner):
                return

        master = self.USERS[MASTER_IDENTIFIER]
        total_amount = 0
        for tx in block.tx_list:
            total_amount += tx.amount
        reward = max(len(str(total_amount)) - 1, 1)

        tr = self.create_transaction(master, user, reward, label='Reward')

        if not tr:
            return

        block.tx_list.append(tr)

    def send_coin(self, user_from, user_to, amount, label='Transaction'):
        last_block = self.BLOCK_CHAIN[len(self.BLOCK_CHAIN) - 1]
        tx = self.create_transaction(user_from, user_to, amount, label)

        if tx is None:
            return False

        block = Block(last_block.index + 1, time.time(),
                      last_block.hash, [tx])
        return self.broadcast_miner_compute(block)

    def handle_transaction(self, author, recipient, amount):
        """
            Handle a transaction from an author to a recipient.
            Check the balance and then dispatch the transaction
        """
        if recipient not in self.USERS:
            return {'message': 'Unknown user'}, 400

        if self.get_account_history(author)['balance'] < amount:
            return {'message': 'Unsufficient balance'}, 400

        res = self.send_coin(self.USERS[author], self.USERS[recipient], amount)

        if res:
            return {'message': 'Transaction will be added to block'}, 200
        else:
            return {'message': 'Unable to process the transaction'}, 400

    def exposed_transaction(self, token, recipient, amount):
        """
            Request for a transaction in the blockchain
        """
        res = self.is_user_authenticated(token)

        if not res:
            return {'message': 'Authentication failed'}, 400

        user = res

        return self.handle_transaction(user.email, recipient, amount)

    def exposed_history(self, token):
        res = self.is_user_authenticated(token)

        if not res:
            return {'message': 'Authentication failed'}, 400

        user = res

        history = self.get_account_history(user.email)['history']

        return {'history': history}, 200

    def exposed_get_account(self, token):
        res = self.is_user_authenticated(token)

        if not res:
            return {'message': 'Authentication failed'}, 400

        user = res

        account = self.get_account_history(user.email)

        return {'account': account}, 200

    def exposed_get_balance(self, token):
        res = self.is_user_authenticated(token)

        if not res:
            return {'message': 'Authentication failed'}, 400

        user = res

        balance = self.get_account_history(user.email)['balance']

        return {'balance': balance}, 200

    # }}}
    # Users {{{

    def exposed_authenticate_user(self, email, passwd):
        """
            Allow to authenticate as a user of the blockchain
        """
        user = None

        for k in self.USERS:
            if self.USERS[k].email == email:
                user = self.USERS[k]
                break

        if user is None:
            return {'message': 'Unknown user'}, 400

        try:
            res = user.authenticate(passwd)

            token = {
                'email': user.email,
                'token': res
            }

            _str = json.dumps(token)

            b64 = base64.b64encode(_str)

            cipher = Fernet(self.SECRET_KEY)
            encrypted = cipher.encrypt(b64)

            return {'message': 'Successfully authenticated',
                    'token': encrypted, 'email': user.email,
                    'name': user.name, 'services': user.services}, 201
        except AuthenticationError:
            return {'message': 'Authentication failed'}, 400
        except Exception:
            return {'message': 'Unknown error while trying to authenticate'}, \
                    400

    def _authenticate_master(self, priv):
        return priv == self.USERS[MASTER_IDENTIFIER].private_key

    def is_user_authenticated(self, token):
        cipher = Fernet(self.SECRET_KEY)
        ts = cipher.extract_timestamp(token)
        now = int(time.time())

        if (now - ts) > DEFAULT_EXPIRY:
            return False

        b64 = cipher.decrypt(token)
        plain = base64.b64decode(b64)
        _json = json.loads(plain)

        user = self.USERS[_json['email']]

        if user is None:
            return False

        if user.is_authenticated(_json['token']):
            return user
        else:
            return False

    def _create_user(self, name, email, passwd, admin):
        if email not in self.USERS:
            sha_passwd = hashlib.sha256()
            sha_passwd.update(passwd.encode('utf-8'))
            user = User(name, email, sha_passwd.hexdigest(), admin=admin)
            self.USERS[email] = user

            return True

        return False

    def exposed_master_create_user(self, priv, *args):
        res = self._authenticate_master(priv)

        if not res:
            return {'message': 'Authentication failed'}, 400

        if self._create_user(*args):
            return {'message': 'User successfully created'}, 200
        else:
            return {'message': 'Failed to create the user'}, 400

    def exposed_master_credit(self, priv, recipient, amount):
        if priv != self.USERS[MASTER_IDENTIFIER].private_key:
            return {'message': 'Authentication failed'}, 400

        return self.handle_transaction(MASTER_IDENTIFIER, recipient, amount)

    def exposed_declare_service(self, token, role):
        res = self.is_user_authenticated(token)

        if not res:
            return {'message': 'Authentication failed'}, 400

        user = res

        service = user.declare_service(role)

        return {'message': 'Service declared successfully',
                'serviceKey':  service['key']}, 200

    def exposed_list_users(self, token):
        res = self.is_user_authenticated(token)

        if not res:
            return {'message': 'Authentication failed'}, 400

        user = res

        users = [{'name': self.USERS[k].name, 'email': self.USERS[k].email}
                 for k in self.USERS
                 if self.USERS[k].email != user.email
                 and self.USERS[k].email != MASTER_IDENTIFIER]

        return {'users': users}, 200

    def exposed_service_refresh_key(self, token, key):
        res = self.is_user_authenticated(token)

        if not res:
            return {'message': 'Authentication failed'}, 400

        user = res

        new_key, err = user.service_refresh_key(key)

        if err:
            return {'message': 'Could not change the service key'}, 400

        # TODO: Key has changed, miner must be delogged

        return {'key': new_key}, 200

    # }}}
    # {{{ Services

    def exposed_auth_service(self, token, owner, key):
        try:
            user = self.USERS[owner]
            found = False

            for s in user.services:
                if s['key'] == key:
                    found = True
                    break

            if not found:
                return False, 400
        except KeyError:
            return False, 400

        return \
            super(BlockChainService, self).exposed_auth_service(token, owner,
                                                                key)

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
                              protocol_config={"allow_pickle": True})

    server.load_state(conf)

    def signal_handler(sig, frame):
        server.save_state(conf)
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    logger.info('Server up and running')

    server.start()
