#!/usr/bin/python

# Blockchain website

import os
import socket
import requests
import flask
from flask import Flask, render_template, jsonify, request, session
from flask_session import Session
from flask_cors import CORS, cross_origin
import logging
import json
from copy import deepcopy

import rpyc

from src import utils

app = Flask(__name__)
CORS(app, supports_credentials=True)

logger = logging.getLogger('blockchain')
hdlr = logging.FileHandler('log/blockchain.log')

formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr)

# {{{ API

class BlockchainApi:
    def get_connection(self):
        global conf

        return rpyc.connect(host = conf['server']['ip'],
                            port = conf['server']['port'])

    def request_auth(self, email, passwd):
        conn = self.get_connection()

        return conn.root.authenticate_user(email, passwd)

    def request_send_coin(self, token, values):
        conn = self.get_connection()

        return conn.root.transaction(token, values['recipient'], int(values['amount']))

    def request_account(self, token):
        conn = self.get_connection()

        return conn.root.get_account(token)

    def request_list_users(self, token):
        conn = self.get_connection()

        response = conn.root.list_users(token)

        # By default, exclude master from API
        if 'users' in response:
            response['users'] = [u for u in response['users'] if u['email'] != 'master@intersec.com']

        return response

# }}}
# {{{ Website

@app.route('/auth', methods=['POST'])
@cross_origin()
def authenticate():
    global API

    login = None
    password = None

    if request.form is not None:
        login = request.form['login']
        password = request.form['password']

    if login is None or password is None:
        return jsonify({'message': 'Missing request parameters'}), 400

    res = API.request_auth(login, password)

    if 'token' in res:
        session['token'] = res['token']
        session['email'] = res['email']
        session['name'] = res['name']

    return jsonify({ 'message': res['message'] }), res['code']

@app.route('/account/get', methods=['POST'])
@cross_origin()
def get_account():
    global API

    if not 'token' in session:
        return jsonify({'message': 'Unknown session, cannont get the account'}), 400

    logger.debug('Ask for history')
    response = API.request_account(session['token'])

    if 'account' in response:
        # Deep copy because the response is not serializable,
        # for an unknown reason
        ac = deepcopy(response['account'])

        return jsonify({ 'account': ac }), response['code']

    return jsonify({ 'message': response['message'] }), response['code']

@app.route('/transaction/new', methods=['POST'])
@cross_origin()
def new_transaction():
    global API

    values = request.form

    required = ['recipient', 'amount']
    if not all(k in values for k in required):
        return jsonify({'message': 'Error when trying to create transaction'}), 400

    # Create transaction for the blockchain
    logger.debug('Ask for new transaction')

    response = API.request_send_coin(session['token'], values)

    return jsonify(response['message']), response['code']

@app.route('/users/list', methods=['POST'])
@cross_origin()
def list_users():
    global API

    response = API.request_list_users(session['token'])

    if 'users' in response:
        # Not serialize, must be copied...
        users = deepcopy(response['users'])
        return jsonify(users), response['code']

    return jsonify({ 'message': response['message'] }), response['code']

@app.route('/exit', methods=['GET'])
def exit():
    session.clear()

    return index()

@app.route('/account')
def account():
    return render_template('./account.html')

@app.route('/history')
def history():
    return render_template('./history.html')

@app.route('/transaction')
def transaction():
    return render_template('./transaction.html')

@app.route('/auth_form')
def auth_form():
    return render_template('./auth_form.html')

@app.route('/')
def index():
    if 'token' in session:
        return account()
    else:
        return auth_form()

# }}}

conf = None

if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-c', '--conf',
                        help='server configuration file')

    args = parser.parse_args()
    conf = utils.load_configuration_file(args.conf)

    app.config.update(
        SECRET_KEY=conf['secretKey'],
        SESSION_COOKIE_HTTPONLY=False,
        SESSION_COOKIE_SECURE=False,
        SESSION_COOKIE_PATH='/',
        SESSION_TYPE = 'filesystem',
    )

    Session(app)

    API = BlockchainApi()

    app.run(host='{0}.corp'.format(socket.gethostname()), port=5000)
