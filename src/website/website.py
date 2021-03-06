#!/usr/bin/python

# Blockchain website

from flask import Flask, render_template, jsonify, request, session
from flask_session import Session
from flask_cors import CORS, cross_origin
from copy import deepcopy
import socket
import json

import rpyc

from src.utils import load_configuration_file, get_logger_by_name

app = Flask(__name__, static_url_path='/src/website/static')
CORS(app, supports_credentials=True)

# {{{ Logger

logger = get_logger_by_name('website')

# }}}
# {{{ API


class BlockchainApi:
    def on_authentication_failed(self):
        session.clear()

    def get_connection(self):
        global conf

        return rpyc.connect(host=conf['server']['ip'],
                            port=conf['server']['port'])

    def request_auth(self, email, passwd):
        conn = self.get_connection()

        return conn.root.authenticate_user(email, passwd)

    def request_send_coin(self, token, values):
        conn = self.get_connection()

        response, code = conn.root.transaction(token, values['recipient'],
                                               int(values['amount']))

        if 'code' in response and response['code'] == 'AUTH_FAIL':
            self.on_authentication_failed()

        return response, code

    def request_account(self, token):
        conn = self.get_connection()

        response, code = conn.root.get_account(token)

        if 'code' in response and response['code'] == 'AUTH_FAIL':
            self.on_authentication_failed()

        return response, code

    def get_last_trs(self, token, ts):
        conn = self.get_connection()

        response, code = conn.root.get_last_trs(token, ts)

        if 'code' in response and response['code'] == 'AUTH_FAIL':
            self.on_authentication_failed()

        return response, code

    def request_list_users(self, token):
        conn = self.get_connection()

        response, code = conn.root.list_users(token)

        if 'code' in response and response['code'] == 'AUTH_FAIL':
            self.on_authentication_failed()

        return response, code

    def service_refresh_key(self, token, key):
        conn = self.get_connection()

        response = conn.root.service_refresh_key(token, key)

        if 'code' in response and response['code'] == 'AUTH_FAIL':
            self.on_authentication_failed()

        return response

    def get_services_status(self, token):
        conn = self.get_connection()

        response = conn.root.get_services_status(token)

        if 'code' in response and response['code'] == 'AUTH_FAIL':
            self.on_authentication_failed()

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

    res, code = API.request_auth(login, password)

    if 'token' in res:
        session['token'] = res['token']
        session['email'] = res['email']
        session['name'] = res['name']
        session['services'] = res['services']

    return jsonify({'message': res['message']}), code


@app.route('/account/get', methods=['POST'])
@cross_origin()
def get_account():
    global API

    if 'token' not in session:
        return jsonify({'message': 'Unknown session, \
                                    cannot get the account'}), 400

    logger.debug('Asking for history')
    response, code = API.request_account(session['token'])

    if 'account' in response:
        # Deep copy because the response is not serializable,
        # for an unknown reason
        ac = deepcopy(response['account'])

        return jsonify({'account': ac}), code

    return jsonify({'message': response['message']}), code


@app.route('/transaction/new', methods=['POST'])
@cross_origin()
def new_transaction():
    global API

    values = request.form

    required = ['recipient', 'amount']
    if not all(k in values for k in required):
        return jsonify({'message': 'Error when trying \
                                    to create transaction'}), 400

    # Create transaction for the blockchain
    logger.debug('Ask for new transaction')

    response, code = API.request_send_coin(session['token'], values)

    return jsonify(response['message']), code


@app.route('/users/list', methods=['POST'])
@cross_origin()
def list_users():
    global API

    response, code = API.request_list_users(session['token'])

    if 'users' in response:
        # Not serialized, must be copied...
        users = deepcopy(response['users'])
        return jsonify(users), code

    return jsonify({'message': response['message']}), code


@app.route('/service/refresh-key', methods=['POST'])
@cross_origin()
def service_refresh_key():
    global API

    key = request.form['key']

    response, code = API.service_refresh_key(session['token'], key)

    if 'key' in response:
        for s in session['services']:
            if s['key'] == key:
                s['key'] = response['key']
                break

        return jsonify({'key': response['key']}), code
    else:
        return jsonify({'message': response['message']}), code


@app.route('/service/status', methods=['POST'])
@cross_origin()
def get_services_status():
    global API

    if 'token' not in session:
        return jsonify({'message': 'Unknown session, \
                                    cannot get the account'}), 400

    response, code = API.get_services_status(session['token'])

    if 'statuses' in response:
        # Not serialized, must be copied...
        statuses = deepcopy(response['statuses'])

        return jsonify({'statuses': statuses}), code
    else:
        return jsonify({'message': response['message']}), code


@app.route('/transaction/last', methods=['POST'])
def get_last_transaction():
    global API

    if 'token' not in session:
        return jsonify({'message': 'Unknown session, \
                                    cannot get the account'}), 400

    _str = request.get_data()
    _json = json.loads(_str)

    since = _json['since']

    if not since:
        return jsonify({'message': 'Missing "since" parameter'}), 400

    response, code = API.get_last_trs(session['token'], since)

    if 'lastTransactions' in response:
        # Not serialized, must be copied...
        last_transactions = deepcopy(response['lastTransactions'])

        return jsonify({'lastTransactions': last_transactions}), code
    else:
        return jsonify({'message': response['message']}), code


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
                        help='website configuration file')

    args = parser.parse_args()
    conf = load_configuration_file(args.conf)

    app.config.update(
        SECRET_KEY=conf['secretKey'],
        SESSION_COOKIE_HTTPONLY=False,
        SESSION_COOKIE_SECURE=False,
        SESSION_COOKIE_PATH='/',
        SESSION_TYPE='filesystem',
    )

    Session(app)

    API = BlockchainApi()

    app.run(host=socket.gethostname(), port=conf['port'])
