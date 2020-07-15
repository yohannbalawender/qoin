#!/usr/bin/python

import os
import socket
import signal
import sys
import stat
import json
import base64
from argparse import ArgumentParser

import rpyc

from src.utils import load_configuration_file
from src.services.node import Leader
from src.blockchain import Block, Transaction


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

    def save_blockchain(self, conf):
        def set_internal_dir(path):
            os.mkdir(path)
            # Read and execute owner permission
            os.chmod(path, stat.S_IRUSR | stat.S_IXUSR)

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

    def set_blockchain(self, BLOCK_CHAIN):
        """
            Store the blockchain reference
        """

        self.BLOCK_CHAIN = BLOCK_CHAIN


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

    server = BlockChainServer(BlockChainService,
                              hostname=hostname, port=conf['port'],
                              protocol_config={"allow_public_attrs": True,
                                               "allow_pickle": True})

    server.load_blockchain(conf)

    def signal_handler(sig, frame):
        server.save_blockchain(conf)
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    server.start()
