#!/usr/bin/python

from block import Block
from transaction import Transaction
from user import User, AuthenticationError
from utils import load_configuration_file
import time

import json
import socket
from argparse import ArgumentParser
import base64
from collections import OrderedDict
import threading

import signal
import sys
import os
import hashlib
import logging
from cryptography.fernet import Fernet

import rpyc
from rpyc.utils.server import ThreadedServer

logger = logging.getLogger('blockchain')
hdlr = logging.FileHandler('log/blockchain.log')

formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr)

DEFAULT_EXPIRY = 86400 * 90

############################################################################
conf = {}
BLOCK_CHAIN = []
USERS = {}
SERVICES = {}
PENDING_BLOCKS = {}
SECRET_KEY = None

def init(conf):
    global SECRET_KEY

    SECRET_KEY = conf['secretKey'].encode('ascii')

    if SECRET_KEY is None:
        raise Exception('Missing key')

def dump_block_chain():
    for block in BLOCK_CHAIN:
        print block

def create_transaction(sender, receiver, amount):
    return Transaction(sender, receiver, amount, time.time())

def create_genesis_block():
    tx    = Transaction(USERS['master@intersec.com'],
                        USERS['master@intersec.com'],
                        conf['defaultGenesisAmount'], time.time())
    block = Block(0, time.time(), None, [tx])
    nonce, hash = block.gen_hash()
    block.set_hash(nonce, hash)
    return block

def create_user(name, email, passwd):
    if email not in USERS:
        sha_passwd = hashlib.sha256()
        sha_passwd.update(passwd.encode('utf-8'))
        user = User(name, email, sha_passwd.hexdigest())
        USERS[email] = user

        return True

    return False

def restore_block_chain_from_json(data):
    prev_hash = None

    for s_block in data:
        block = Block(None, None, None, None)
        tx_list = []

        for s_tx in s_block['tx_list']:
            tx = Transaction(None, None, s_tx['amount'], s_tx['ts'])
            tx.snd = base64.b64decode(s_tx['snd'])
            tx.rcv = base64.b64decode(s_tx['rcv'])
            tx.signature = base64.b64decode(s_tx['signature'])
            tx_list.append(tx)

        block.index     = s_block['index']
        block.ts        = s_block['ts']
        block.prev_hash = s_block['prev_hash']
        block.tx_list   = tx_list
        block.nonce     = s_block['nonce']
        block.hash      = s_block['hash']

        # Checks
        if not block.check_validity():
            raise Exception('Cannot restore the blockchain because a signature is invalid')

        if s_block['index'] > 0:
            if s_block['prev_hash'] != prev_hash:
                raise Exception('Cannot restore the blockchain because hash is invalid')

        print block
        BLOCK_CHAIN.append(block)

        prev_hash = s_block['hash']

def restore_users_from_json(data):
    for s_user in data:
        user = User(s_user['name'], s_user['email'], s_user['passwd'],
                    priv = base64.b64decode(s_user['private_key']),
                    pub = base64.b64decode(s_user['public_key']),
                    salt = s_user['salt'])
        print user
        USERS[user.email] = user
    print '='*20

def restore_services_from_json(data):
    i = 0

    for s_service in data:
        SERVICES[(s_service['host'], s_service['port'], s_service['role'])] = 1
        i += 1

    print '%d services restored' % i

def load_block_chain():
    filepath = conf['blockchainDir'] + '/dump.json'
    if not os.path.isfile(filepath):
        return

    with open(filepath) as json_file:
        data = json.load(json_file)
        restore_block_chain_from_json(data)

def load_users():
    filepath = conf['usersDir'] + '/dump.json'
    if not os.path.isfile(filepath):
        return

    with open(filepath) as json_file:
        data = json.load(json_file)
        restore_users_from_json(data)

def load_services():
    filepath = conf['servicesDir'] + '/dump.json'
    if not os.path.isfile(filepath):
        return

    with open(filepath) as json_file:
        data = json.load(json_file)
        restore_services_from_json(data)

def save_block_chain():
    if not os.path.exists(conf['blockchainDir']):
        os.mkdir(conf['blockchainDir'])

    blocks = []
    for block in BLOCK_CHAIN:
        print block
        blocks.append(block.serialize())

    with open(conf['blockchainDir'] + '/dump.json', 'w') as outfile:
            json.dump(blocks, outfile)

def save_users():
    if not os.path.exists(conf['usersDir']):
        os.mkdir(conf['usersDir'])

    users = []
    for k in USERS:
        users.append(USERS[k].serialize())

    # TODO: right permission on user folder
    with open(conf['usersDir'] + '/dump.json', 'w') as outfile:
        json.dump(users, outfile)

def save_services():
    if not os.path.exists(conf['servicesDir']):
        os.mkdir(conf['servicesDir'])

    services = []

    for s in SERVICES:
        services.append({ 'host': s[0], 'port': s[1], 'role': s[2] })

    with open(conf['servicesDir'] + '/dump.json', 'w') as outfile:
        json.dump(services, outfile)

def signal_handler(sig, frame):
    save_block_chain()
    save_users()
    save_services()
    sys.exit(0)

def get_user_from_public_key(pub):
    for k in USERS:
        if USERS[k].public_key == pub:
            return USERS[k]
    return None

def is_user_authenticated(token, err = []):
    cipher = Fernet(SECRET_KEY)
    ts = cipher.extract_timestamp(token)
    now = int(time.time())

    if (now - ts) > DEFAULT_EXPIRY:
        err.append({'code': 400, 'message': 'Authentication expired'})

        return None

    b64 = cipher.decrypt(token)
    plain = base64.b64decode(b64)
    _json = json.loads(plain)

    user = USERS[_json['email']]

    if user is None:
        err.append({'code': 400, 'message': 'Unknown session'})

        return None

    if user.is_authenticated(_json['token']):
        return user
    else:
        err.append({'code': 400, 'message': 'Fail to authenticate'})
        return None

def get_account_history(user_email):
    balance = 0
    history = OrderedDict()
    user = USERS[user_email]

    for block in BLOCK_CHAIN:
        for tx in block.tx_list:
            if tx.rcv == user.public_key:
                balance += tx.amount
                tx_user = get_user_from_public_key(tx.snd)
                history[tx.ts] = {
                    'amount': tx.amount,
                    'name': tx_user.name,
                    'email': tx_user.email,
                    'label': tx.label
                }
            elif tx.snd == user.public_key:
                balance -= tx.amount
                tx_user = get_user_from_public_key(tx.rcv)
                history[tx.ts] = {
                    'amount': -tx.amount,
                    'name': tx_user.name,
                    'email': tx_user.email,
                    'label': tx.label
                }
    return { 'history': history, 'balance': balance }

###########################################################################

class BlockChainService(rpyc.Service):
    def on_connect(self, conn):
        print 'New connection accepted'

    def on_disconnect(self, conn):
        print 'Connection closed'

    def exposed_register_miner(self, host, port):
        SERVICES[(host, int(port), 'MINER')] = 1

        logger.info('Miner registration succeed')

        return None

    def exposed_register_qwinner(self, host, port):
        SERVICES[(host, int(port), 'QWINNER')] = 1

        logger.info('Qwinner registration succeed')

        return None

    def handle_transaction(self, author, recipient, amount):
        if recipient not in USERS:
            return { 'code': 400, 'message': 'Unknown user' }

        if get_account_history(author)['balance'] < amount:
            return { 'code': 400, 'message': 'Unsufficient balance' }

        res = self.send_coin(USERS[author], USERS[recipient], amount, 'Transaction')

        if res:
            return { 'code': 200, 'message': 'Transaction will be added to block' }
        else:
            return { 'code': 400, 'message': 'Unable to process the transaction' }

    def exposed_master_credit(self, priv, recipient, amount):
        email = 'master@intersec.com'

        if priv != USERS[email].private_key:
            return { 'code': 400, 'message': 'Unable to process the transaction' }

        self.handle_transaction(email, recipient, amount)

    def exposed_transaction(self, token, recipient, amount):
        err = []
        user = is_user_authenticated(token, err)

        if err:
            return err[0]

        email = user.email

        return self.handle_transaction(email, recipient, amount)

    def exposed_history(self, token):
        err = []
        user = is_user_authenticated(token, err)

        if err:
            return err[0]

        history = get_account_history(user.email)['history']

        return { 'code': 200, 'history': history }

    def exposed_get_account(self, token):
        logger.debug('Request account for token %s' % (token))

        err = []
        user = is_user_authenticated(token, err)

        if err:
            return err[0]

        account = get_account_history(user.email)

        return { 'code': 200, 'account': account }

    def exposed_get_balance(self, token):
        err = []
        user = is_user_authenticated(token, err)

        if err:
            return err[0]

        balance = get_account_history(user.email)['balance']

        return { 'code': 200, 'balance': balance }

    def exposed_on_gerrit_notify(self, data):
        if data['email'] not in USERS:
            return { 'code': 400, 'message': 'Unknown user' }

        data_reward = self.get_data_reward(data)

        self.send_coin(USERS['master@intersec.com'], USERS[data['email']],
                       data_reward['amount'], 'Reward')

        return {'code': 200, 'message': 'Gerrit reward will be added to block'}

    def get_data_reward(self, data):
        # TODO: choose the right Qwinner
        for s in SERVICES:
            if s[2] == 'QWINNER':
                qwinner = s
                break

        try:
            conn = rpyc.connect(host = qwinner[0], port = qwinner[1], config = { 'allow_all_attrs': True })
        except:
            print 'Connection lost with qwinner %s' % (qwinner.__str__())
            return

        resp = conn.root.compute_reward(data)

        return { 'code': 200, 'rewarded': data['email'], 'amount': resp['value'] }

    def send_miner_compute(self, miner, block):
        try:
            conn = rpyc.connect(host = miner[0], port = miner[1], config = { 'allow_all_attrs': True })
        except:
            SERVICES.pop(miner)
            print 'Connection lost with miner %s' % (miner.__str__())
            return

        data = block.serialize()

        response = conn.root.compute_hash(data)

        self.miner_hash_result(miner, response)

    def miner_hash_result(self, miner, response):
        s_block = response['result']['block']
        key = (s_block['index'], s_block['ts'], s_block['prev_hash'])
        if key in PENDING_BLOCKS:
            block = PENDING_BLOCKS[key]

            # TODO verif
            if not block.check_hash_validity(s_block['nonce'] , s_block['hash']):
                print 'Miner %s sent an invalid hash' % (miner.__str__())
                return

            block.set_hash(s_block['nonce'] , s_block['hash'])
            print 'Solved by miner %s, good job ! ' % (miner.__str__())
            PENDING_BLOCKS.pop(key, None)
            BLOCK_CHAIN.append(block)
        else:
            print 'Bad luck, block already solved'

    def broadcast_miner_compute(self, block):
        cnt = 0
        miners = []

        for s in SERVICES:
            # s[2] is the role of the service
            if s[2] == 'MINER':
                miners.append(s)
                cnt += 1

        if cnt == 0:
            logger.error('No miner service available to procede the transaction. Transaction is lost')
            return False

        PENDING_BLOCKS[(block.index, block.ts, block.prev_hash)] = block

        for m in miners:
            thr = threading.Thread(target=self.send_miner_compute,
                                   args=(m, block,))
            thr.start()

        return True

    def send_coin(self, user_from, user_to, amount, label='Transaction'):
        last_block = BLOCK_CHAIN[len(BLOCK_CHAIN) - 1]
        tx = create_transaction(user_from, user_to, amount)
        tx.label = label

        block = Block(last_block.index + 1, time.time(),
                      last_block.hash, [tx])
        return self.broadcast_miner_compute(block)

    # Users {{{

    def exposed_authenticate_user(self, email, passwd):
        user = None

        for k in USERS:
            if USERS[k].email == email:
                user = USERS[k]
                break

        if user is None:
            return { 'code': 400, 'message': 'Unknown user' }

        try:
            res = user.authenticate(passwd)

            token = {
                'email': user.email,
                'token': res
            }

            _str = json.dumps(token)

            b64 = base64.b64encode(_str)

            cipher = Fernet(SECRET_KEY)
            encrypted = cipher.encrypt(b64)

            return { 'code': 201, 'message': 'Successfully authenticated', 'token': encrypted, 'email': user.email, 'name': user.name }
        except AuthenticationError:
            return { 'code': 400, 'message': 'Authentication failed' }
        except Exception:
            return { 'code': 400, 'message': 'Unknown error while trying to authenticate' }

    def exposed_create_user(self, name, email, passwd):
        res = create_user(name, email, passwd)

        if res:
            return { 'code': 200, 'message': 'User successfully created' }

        return { 'code': 400, 'message': 'Failed to create user' }

    def exposed_list_users(self, token):
        err = []
        user = is_user_authenticated(token, err)

        if err:
            return err[0]

        users = [{ 'name': USERS[k].name, 'email': USERS[k].email }
                 for k in USERS if USERS[k].email != user.email]

        return { 'code': 200, 'users': users }

    # }}}

###########################################################################


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('-c', '--conf',
                        help='server configuration file')

    args = parser.parse_args()
    conf = load_configuration_file(args.conf)

    init(conf)

    load_users()
    load_services()

    create_user('master', 'master@intersec.com', 'master')
    create_user('ndiaga', 'ndiaga.dieng@intersec.com', 'ndiaga')
    create_user('yohann', 'yohann.balawender@intersec.com', 'yohann')
    create_user('jeanmarc', 'jean-marc.coic@intersec.com', 'jeanmarc')

    load_block_chain()
    if len(BLOCK_CHAIN) == 0:
        BLOCK_CHAIN.append(create_genesis_block())

    signal.signal(signal.SIGINT, signal_handler)

    server = ThreadedServer(BlockChainService, hostname = socket.gethostname(),
                            port = conf['port'],
                            protocol_config = {"allow_public_attrs" : True,
                                               "allow_pickle": True })
    server.start()


