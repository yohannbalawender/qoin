#!/usr/bin/python

from block import Block
from transaction import Transaction
from utils import load_configuration_file

import sys

import json
import socket
from argparse import ArgumentParser
import base64
import threading
import ecdsa
import os

import rpyc
from rpyc.utils.server import ThreadedServer

conf = {}

class MinerServer(ThreadedServer):
    def on_connect(self, conn):
        print 'Server is connected'

    def on_disconnect(self, conn):
        print 'Server is disconnected'

    def set_server_addr(self, host, port):
        self.server_host = host
        self.server_port = port

    def register(self):
        if self.server_host is None or self.server_port is None:
            raise BaseException('Cannot register on an unknown server')

        conn = self.get_connection()

        res = conn.root.register_miner(self.host, self.port)

        if res is not None:
            raise BaseException('Failed to register miner')
        else:
            print 'Miner successfully registered'

        conn.close()

    def get_connection(self):
        return rpyc.connect(self.server_host, self.server_port)


class MinerClient(rpyc.Service):
    def exposed_compute_hash(self, s_block):
        print '='*20
        if not check_block(s_block):
            print 'Block signature verification failed'
            
            return {'code': 400, 'message': 'Invalid block: miner reject it'}

        print 'Block signature verification succeed'

        result = self.compute_block_hash(s_block)

        return {'code': 200, 'result': result}

    def compute_block_hash(self, s_block):
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

        nonce, hash = block.gen_hash()
        block.set_hash(nonce, hash)

        return {'block' : block.serialize() }

def check_block(block):
    valid = True

    for s_tx in block['tx_list']:
        vk_str = base64.b64decode(s_tx['snd'])
        vk = ecdsa.VerifyingKey.from_string(vk_str, curve=ecdsa.SECP256k1)

        msg = '%d%s%s%d' % (s_tx['amount'],
                            base64.b64decode(s_tx['snd']),
                            base64.b64decode(s_tx['rcv']),
                            s_tx['ts'])

        valid = valid and vk.verify(base64.b64decode(s_tx['signature']),
                                    msg)

    return valid

###########################################################################

if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('-c', '--conf',
                        help='server configuration file')

    args = parser.parse_args()
    conf = load_configuration_file(args.conf)

    if conf['server'] is None or conf['server']['ip'] is None \
        or conf['server']['port'] is None:
        raise 'Server must be provided in the configuration file'

    server_host = conf['server']['ip']
    server_port = conf['server']['port']
    client_port = conf['port']

    server = MinerServer(MinerClient, hostname = socket.gethostname(),
                         port = client_port)

    server.set_server_addr(server_host, server_port)

    server.register()

    print 'Miner service is running'

    server.start()
