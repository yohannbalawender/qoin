#!/usr/bin/python

import sys
import os
from block import Block
from transaction import Transaction
import json
from argparse import ArgumentParser
import socket
import math

from utils import load_configuration_file

import rpyc
from rpyc.utils.server import ThreadedServer

# {{{ Qwinner utils

conf = {}

class QwinnerServer(ThreadedServer):
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

        res = conn.root.register_qwinner(self.host, self.port)

        if res is not None:
            raise BaseException('Failed to register qwinner')
        else:
            print 'Qwinner successfully registered'

        conn.close()

    def get_connection(self):
        return rpyc.connect(self.server_host, self.server_port)


class QwinnerClient(rpyc.Service):
    def exposed_compute_reward(self, data):
        value = data['length'] + data['nb_files'] + math.ceil((data['nb_insertions']
                                                             +
                                                             data['nb_deletions'])/100.)

        return { 'value': value }

# }}}

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

    server = QwinnerServer(QwinnerClient, hostname = socket.gethostname(),
                           port = client_port)

    server.set_server_addr(server_host, server_port)

    server.register()

    print 'Qwinner service is running'

    server.start()

