#!/usr/bin/python

import base64
import socket
from argparse import ArgumentParser

import rpyc

from src.utils import load_configuration_file, get_logger_by_name
from src.services.node import Follower
from src.blockchain import Block, Transaction

# {{{ Logger

logger = get_logger_by_name('miner')

# }}}


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


class MinerServer(Follower):
    """
        Implementation of a miner service in the cluster
    """

    role = 'MINER'
    credentials = None

    def set_credentials(self, credentials):
        self.credentials = (credentials['owner'], credentials['key'])


class MinerClient(rpyc.Service):
    def exposed_compute_hash(self, s_block):
        logger.debug('Computing block hash...')

        block = get_block_obj(s_block)

        result = self.compute_block_hash(block)

        return {'code': 200, 'result': result}

    def compute_block_hash(self, block):
        nonce, hash = block.gen_hash()
        logger.debug('Block nonce found')

        block.set_hash(nonce, hash)

        return {'block': block.serialize()}


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('-c', '--conf',
                        help='server configuration file')

    args = parser.parse_args()
    conf = load_configuration_file(args.conf)

    if conf['leader'] is None \
        or conf['leader']['ip'] is None \
        or conf['leader']['port'] is None:

        raise 'Server must be provided in the configuration file'

    leader_host = conf['leader']['ip']
    leader_port = conf['leader']['port']
    client_port = conf['port']

    server = MinerServer(MinerClient(), hostname=socket.gethostname(),
                         port=client_port)

    server.set_leader_addr(leader_host, leader_port)

    token = server.retry(3, server.register, conf)

    try:
        cr = conf['credentials']

        res, code = server.authenticate(token, cr['owner'], cr['key'])

        if res:
            logger.info('Miner successfully authenticated')
        else:
            logger.error('Fail to authenticate miner')
    except KeyError:
        pass

    logger.info('Miner up and running')

    server.start()
