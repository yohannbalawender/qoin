#!/usr/bin/python

# Blockchain website

import socket
import requests
from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
import logging
import json
from copy import deepcopy

import rpyc

from src import utils

app = Flask(__name__)
CORS(app)

logger = logging.getLogger('blockchain')
hdlr = logging.FileHandler('log/blockchain.log')

formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr)

# {{{ API

class BlockchainApi:
    def request_send_coin(self, values):
        global conf

        conn = rpyc.connect(host = conf['server']['ip'], port = conf['server']['port'])

        return conn.root.transaction(values['login'], values['password'], values['recipient'], int(values['amount']))

    def request_account(self, login, passwd):
        global conf

        conn = rpyc.connect(host = conf['server']['ip'],
                            port = conf['server']['port'])

        return conn.root.get_account(login, passwd)

# }}}
# {{{ Website

@app.route('/account/get', methods=['GET'])
def get_account():
    global API

    login = request.args.get('login', type = str)
    password = request.args.get('password', type = str)

    if login is None or password is None:
        return jsonify({'message': 'Login and password arguments must be '
                                   'provided to get the account'}), 400

    logger.debug('Ask for history')

    response = API.request_account(login, password)

    # Deep copy because the response is not serializable,
    # for an unknown reason
    ac = deepcopy(response['account'])

    return jsonify({ 'account': ac }), response['code']

@app.route('/transaction/new', methods=['POST'])
def new_transaction():
    global API

    values = request.form

    required = ['login', 'password', 'recipient', 'amount']
    if not all(k in values for k in required):
        return jsonify({'message': 'Error when trying to create transaction'}), 400

    # Create transaction for the blockchain
    logger.debug('Ask for new transaction')

    response = API.request_send_coin(values)

    return jsonify(response['message']), response['code']

@app.route('/account')
def balance():
    return render_template('./account.html')

@app.route('/transaction')
def transaction():
    return render_template('./transaction.html')

@app.route('/')
def index():
    return render_template('./index.html')

# }}}

conf = None

if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-c', '--conf',
                        help='server configuration file')

    args = parser.parse_args()
    conf = utils.load_configuration_file(args.conf)

    API = BlockchainApi()

    app.run(host='{0}.corp'.format(socket.gethostname()), port=5000)
