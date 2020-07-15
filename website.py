#!/usr/bin/python

# Blockchain website

import socket
import requests
from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
import logging
import json

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
    def __init__(self):
        global conf

        self.server = conf['server']

    def request_send_coin(self, values):
        return requests.post(self.server + '/transaction',
                             data=json.dumps(values),
                             headers={'content-type':'application/json'})

    def request_account(self, name):
        return requests.get(self.server + '/account?name=%s' % (name),
                            headers={'content-type':'application/json'})

# }}}
# {{{ Website

@app.route('/account/get', methods=['GET'])
def get_account():
    global API

    name = request.args.get('name', type = str)

    if name is None:
        return jsonify({'message': 'Name argument must be provided to get the'
                                   ' account'}), 400

    logger.debug('Ask for history')

    response = API.request_account(name)

    return jsonify(response.json()), response.status_code

@app.route('/transaction/new', methods=['POST'])
def new_transaction():
    global API

    values = request.form

    required = ['sender', 'recipient', 'amount']
    if not all(k in values for k in required):
        return jsonify({'message': 'Error when trying to create transaction'}), 400

    # Create transaction for the blockchain
    logger.debug('Ask for new transaction')

    response = API.request_send_coin(values)

    return jsonify(response.json()), response.status_code

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

    conf['server'] = 'http://%s:%s' % (conf['server']['ip'],
                                       conf['server']['port'])

    API = BlockchainApi()

    app.run(host='{0}.corp'.format(socket.gethostname()), port=5000)
