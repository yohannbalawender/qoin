#!/usr/bin/python

from block import Block
from transaction import Transaction
from user import User
from utils import load_configuration_file
import time

import json
import socket
from flask import Flask, jsonify, request
from flask_cors import CORS
from argparse import ArgumentParser
import requests
import base64
from collections import OrderedDict

import signal
import sys
import os
import hashlib
############################################################################
conf = {}
BLOCK_CHAIN = []
USERS = {}
MINERS = {}
QWINNERS = {}
PENDING_BLOCKS = {}

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
    return USERS[email]

def restore_block_chain_from_json(data):
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

        print block
        BLOCK_CHAIN.append(block)

def restore_users_from_json(data):
    for s_user in data:
        user = User(s_user['name'], s_user['email'], s_user['passwd'],
                    base64.b64decode(s_user['private_key']),
                    base64.b64decode(s_user['public_key']))
        print user
        USERS[user.email] = user
    print '='*20

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

def signal_handler(sig, frame):
    save_block_chain()
    save_users()
    sys.exit(0)

def broadcast_miner_compute(block):
    data = { 'block': block.serialize() }
    for miner in MINERS:
        address = 'http://%s:%d/compute_hash' % (miner[0], miner[1])
        requests.post(address, data=json.dumps(data, ensure_ascii=False),
                      headers={'Content-Type': 'application/json'})
        PENDING_BLOCKS[(block.index, block.ts, block.prev_hash)] = block

def send_coin(user_from, user_to, amount, label='Transaction'):
    last_block = BLOCK_CHAIN[len(BLOCK_CHAIN) - 1]
    tx = create_transaction(user_from, user_to, amount)
    tx.label = label

    block = Block(last_block.index + 1, time.time(),
                  last_block.hash, [tx])
    broadcast_miner_compute(block)
#    nonce, hash = block.gen_hash()
#    block.set_hash(nonce, hash)
#    BLOCK_CHAIN.append(block)

def get_user_from_public_key(pub):
    for k in USERS:
        if USERS[k].public_key == pub:
            return USERS[k]
    return None

def is_user_authenticated(login, password):
    if login not in USERS:
        return jsonify({'message': 'Unknown user'}), 400

    user = USERS[login]

    if not user.authenticate(password):
        return jsonify({'message': 'Authentication failed'}), 400

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

def get_data_reward(data):
    # Choose the right Qwinner
    qwinner = QWINNERS.keys()[0]

    address = 'http://%s:%d/compute_reward' % (qwinner[0], qwinner[1])
    resp = requests.post(address, data=json.dumps(data, ensure_ascii=False),
                         headers={'Content-Type': 'application/json'})

    _json = resp.json()

    return { 'rewarded': data['email'], 'amount': _json['value'] }

###########################################################################
app = Flask(__name__)
CORS(app)

@app.route('/miner_hash_result', methods=['POST'])
def miner_hash_result():
    response = None
    req = request.get_json()
    s_block = req['block']
    key = (s_block['index'], s_block['ts'], s_block['prev_hash'])
    if key in PENDING_BLOCKS:
        block = PENDING_BLOCKS[key]

        # TODO verif
        if not block.check_hash_validity(s_block['nonce'] , s_block['hash']):
            response = {'message': 'Miner %s send an invalid hash' %
                        request.remote_addr}
            return jsonify(response), 400

        block.set_hash(s_block['nonce'] , s_block['hash'])
        print 'Solved by %s' % request.remote_addr
        PENDING_BLOCKS.pop(key, None)
        BLOCK_CHAIN.append(block)
        response = {'message': 'Good job!'}
    else:
        response = {'message': 'Bad luck, block already solved'}
    return jsonify(response), 200

@app.route('/register_miner', methods=['POST'])
def register_miner():
    req = request.get_json()
    port = req['port']
    MINERS[(request.remote_addr, int(port))] = 1
    response = {'message': 'Miner registration succeed'}
    return jsonify(response), 201

@app.route('/register_qwinner', methods=['POST'])
def register_qwinner():
    req = request.get_json()
    port = req['port']
    QWINNERS[(request.remote_addr, int(port))] = 1
    response = {'message': 'Qwinner registration succeed'}
    return jsonify(response), 201


@app.route('/transaction', methods=['POST'])
def transaction():
    req = request.get_json()

    sender = req['login']
    password = req['password']

    recepient = req['recipient']
    amount = int(req['amount'])

    res =  is_user_authenticated(sender, password)

    if res is not None:
        return res

    if recepient not in USERS:
        return jsonify({'message': 'Unknown user'}), 400

    if get_account_history(sender)['balance'] < amount:
        return jsonify({'message': 'Unsufficient balance'}), 400

    send_coin(sender_user, USERS[recepient], amount, 'Transaction')

    response = {'message': 'Transaction will be added to block'}

    return jsonify(response), 200

@app.route('/balance', methods=['GET'])
def balance():
    login = request.args.get("login")
    password = request.args.get("password")

    res =  is_user_authenticated(login, password)

    if res is not None:
        return res

    balance = get_account_history(login)['balance']

    response = { 'balance': balance }
    return jsonify(response)

@app.route('/history', methods=['GET'])
def history():
    login = request.args.get("login")
    password = request.args.get("password")

    res =  is_user_authenticated(login, password)

    if res is not None:
        return res

    history = get_account_history(login)['history']

    response = { 'history': history }
    return jsonify(response)

@app.route('/account', methods=['GET'])
def get_account():
    login = request.args.get("login")
    password = request.args.get("password")

    res =  is_user_authenticated(login, password)

    if res is not None:
        return res

    account = get_account_history(login)

    response = {'account': account}
    return jsonify(response)

@app.route('/gerrit/notify', methods=['POST'])
def on_gerrit_notify():
    data = request.get_json()

    data_reward = get_data_reward(data)

    send_coin(USERS['master@intersec.com'], USERS[data['email']],
              data_reward['amount'], 'Reward')

    # TODO Check if transaction succeed
    response = {'message': 'Transaction will be added to block'}

    return jsonify(response), 201

if __name__ == '__main__':
    global conf

    parser = ArgumentParser()
    parser.add_argument('-c', '--conf',
                        help='server configuration file')

    args = parser.parse_args()
    conf = load_configuration_file(args.conf)

    load_users()
    create_user('master', 'master@intersec.com', 'master')
    create_user('ndiaga', 'ndiaga.dieng@intersec.com', 'ndiaga')
    create_user('yohann', 'yohann.balawender@intersec.com', 'yohann')
    create_user('jeanmarc', 'jean-marc.coic@intersec.com', 'jeanmarc')

    load_block_chain()
    if len(BLOCK_CHAIN) == 0:
        BLOCK_CHAIN.append(create_genesis_block())

    signal.signal(signal.SIGINT, signal_handler)

    app.run(host='{0}.corp'.format(socket.gethostname()), port=conf['port'])

