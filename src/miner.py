#!/usr/bin/python

from block import Block
from transaction import Transaction
from utils import load_configuration_file

import socket
from argparse import ArgumentParser
import base64

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

    def set_credentials(self, credentials):
        self.credentials = (credentials['owner'], credentials['key'])

    def register(self):
        if self.server_host is None or self.server_port is None:
            raise BaseException('Cannot register on an unknown server')

        conn = self.get_connection()

        try:
            owner, key = self.credentials
        except AttributeError:
            owner = key = None

        res, error = conn.root.register_miner(self.host, self.port, owner, key)

        if not res:
            raise BaseException('Failed to register miner: %s' % (error))
        else:
            print 'Miner successfully registered'

        conn.close()

    def get_connection(self):
        try:
            return rpyc.connect(self.server_host, self.server_port,
                                config={'credentials': ('foo', 'bar')})
        except socket.error:
            raise Exception('Unable to connect master service')


def get_block_obj(s_block):
    block = Block(None, None, None, None)

    tx_list = []

    for s_tx in s_block['tx_list']:
        tx = Transaction(None, None, s_tx['amount'], s_tx['ts'])
        tx.snd = base64.b64decode(s_tx['snd'])
        tx.rcv = base64.b64decode(s_tx['rcv'])
        tx.signature = base64.b64decode(s_tx['signature'])

        tx_list.append(tx)

    block.index = s_block['index']
    block.ts = s_block['ts']
    block.prev_hash = s_block['prev_hash']
    block.tx_list = tx_list

    return block


class MinerClient(rpyc.Service):
    def exposed_compute_hash(self, s_block):
        print '='*20

        block = get_block_obj(s_block)

        if not block.check_validity():
            print 'Block signature verification failed'
            
            return {'code': 400, 'message': 'Invalid block: miner reject it'}

        print 'Block signature verification succeed'

        result = self.compute_block_hash(block)

        return {'code': 200, 'result': result}

    def compute_block_hash(self, block):
        nonce, hash = block.gen_hash()
        block.set_hash(nonce, hash)

        return {'block': block.serialize()}

###########################################################################


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('-c', '--conf',
                        help='server configuration file')

    args = parser.parse_args()
    conf = load_configuration_file(args.conf)

    if conf['server'] is None \
        or conf['server']['ip'] is None \
        or conf['server']['port'] is None:

        raise 'Server must be provided in the configuration file'

    server_host = conf['server']['ip']
    server_port = conf['server']['port']
    client_port = conf['port']

    server = MinerServer(MinerClient, hostname=socket.gethostname(),
                         port=client_port)

    server.set_server_addr(server_host, server_port)

    try:
        credentials = conf['credentials']

        server.set_credentials(credentials)
    except KeyError:
        pass

    server.register()

    print 'Miner service is running'

    server.start()
