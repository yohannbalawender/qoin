#!/usr/bin/python

from block import Block
from transaction import Transaction
from utils import load_configuration_file

import sys

import json
import socket
from flask import Flask, jsonify, request
from flask_cors import CORS
from argparse import ArgumentParser
import requests
import base64
import threading
import ecdsa
import os

conf = {}

def register():
    data = {
        'port': conf['port']
    }
    requests.post('%s/register_miner' % (conf['server']),
                  data=json.dumps(data),
                  headers={'Content-Type': 'application/json'})

def compute_block_hash(s_block):
    block = Block(None, None, None, None)
    tx_list = []

    for s_tx in s_block['tx_list']:
        tx = Transaction(None, None, s_tx['amount'], s_tx['ts'])
        tx.snd = base64.b64decode(s_tx['snd'])
        tx.rcv = base64.b64decode(s_tx['rcv'])
        tx.signature = base64.b64decode(s_tx['signature'])
        tx.vk = base64.b64decode(s_tx['vk'])

        tx_list.append(tx)

    block.index     = s_block['index']
    block.ts        = s_block['ts']
    block.prev_hash = s_block['prev_hash']
    block.tx_list   = tx_list

    nonce, hash = block.gen_hash()
    block.set_hash(nonce, hash)

    result = {'block' : block.serialize() }

    requests.post('%s/miner_hash_result' % (conf['server']),
                  data=json.dumps(result, ensure_ascii=False),
                  headers={'Content-Type': 'application/json'})
    print block

def check_block(block):
    valid = True

    for s_tx in block['tx_list']:
        vk_str = base64.b64decode(s_tx['vk'])
        vk = ecdsa.VerifyingKey.from_string(vk_str, curve=ecdsa.SECP256k1)

        msg = '%d%s%s%d' % (s_tx['amount'],
                            base64.b64decode(s_tx['snd']),
                            base64.b64decode(s_tx['rcv']),
                            s_tx['ts'])

        valid = valid and vk.verify(base64.b64decode(s_tx['signature']),
                                    msg)

    return valid


###########################################################################
app = Flask(__name__)
CORS(app)

@app.route('/compute_hash', methods=['POST'])
def compute_hash():
    req = request.get_json()
    s_block = req['block']

    print '='*20
    if not check_block(s_block):
        print 'Block signature verification failed'
        response = {'message': 'Invalid block: miner reject it'}
        return jsonify(response), 400

    print 'Block signature verification succeed'
    thr = threading.Thread(target=compute_block_hash,
                           args=(s_block,))
    thr.start()
    response = {'message': 'Miner will do the computation'}
    return jsonify(response), 200

if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('-c', '--conf',
                        help='server configuration file')

    args = parser.parse_args()
    conf = load_configuration_file(args.conf)

    conf['server'] = 'http://%s:%s' % (conf['server']['ip'],
                                       conf['server']['port'])

    register()

    app.run(host='{0}.corp'.format(socket.gethostname()), port=conf['port'])

