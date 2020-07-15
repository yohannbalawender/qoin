#!/usr/bin/python

import requests
import json
from argparse import ArgumentParser
from flask import Flask, jsonify, request
from flask_cors import CORS
import socket
import math

from utils import load_configuration_file

# {{{ Qwinner utils

conf = {}

def register():
    data = {
        'port': conf['port']
    }
    requests.post('%s/register_qwinner' % (conf['server']),
                  data=json.dumps(data),
                  headers={'Content-Type': 'application/json'})

# }}}

app = Flask(__name__)
CORS(app)

@app.route('/compute_reward', methods=['POST'])
def compute_reward():
    req = request.get_json()

    value = req['length'] + req['nb_files'] + math.ceil((req['nb_insertions']
                                                         +
                                                         req['nb_deletions'])/100.)
    response = {'value': value}

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

