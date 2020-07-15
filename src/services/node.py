#!/usr/bin/python

import socket
import logging
import hashlib

import rpyc
from rpyc.utils.server import ThreadedServer

# {{{ Loggers

logger = logging.getLogger('blockchain')
hdlr = logging.FileHandler('log/blockchain.log')

formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr)

# }}}


class Node(ThreadedServer):
    node_name = 'Node'

    def on_connect(self, conn):
        logger.info('%s is now connected' % (self.node_name))

    def on_disconnect(self, conn):
        logger.info('%s has disconnected' % (self.node_name))

    def retry(self, nb, fn, *args, **kwargs):
        if nb < 1:
            nb = 1

        def _retry_wrapper():
            while nb:
                try:
                    return fn(**kwargs)
                except BaseException:
                    pass

            return None

        return _retry_wrapper


class Follower(Node):
    """
        A basic class for a following node, allowed to connect to the
        leader
    """

    node_name = 'Follower'
    role = None
    leader_host = None
    leader_port = None

    def set_leader_addr(self, host, port):
        """
            A method used to define the leader host and port
        """

        self.leader_host = host
        self.leader_port = port

    def register(self):
        """
            A method used to register the follower on the leader
        """

        if self.leader_host is None or self.leader_port is None:
            raise BaseException('Cannot register on an unknown leader')

        if self.role is None:
            raise BaseException('Cannot register to the leader with an '
                                'unknown role')

        conn = self._get_connection()

        res, error = conn.root.register(self.leader_host, self.leader_port,
                                        self.role)

        if not res:
            raise BaseException('Failed to register the follower: %s'
                                % (error))

        logger.info('Follower successfully registered')

        conn.close()

    def authenticate(self, owner, key):
        """
            A method used to authenticate a follower to the leader
        """

        conn = self._get_connection()

        res, error = conn.root.auth_service(owner, key)

        if not res:
            raise BaseException('Failed to authenticate the follower: %s'
                                % (error))

        return res

    def _get_connection(self):
        """
            A method used to connect to the leader. Host and port must be
            defined before
        """

        try:
            return rpyc.connect(self.leader_host, self.leader_port)
        except socket.error:
            raise Exception('Unable to connect to the leader')


class Leader(Node):
    node_name = 'Leader'


class LeaderService(rpyc.Service):

    # {{{ Service related

    SERVICES = {}

    def _set_token(self, data):
        return hashlib.sha256(data).hexdigest()

    def _get_services_by_role(self, role):
        services = []

        for _t, _s in self.SERVICES:
            if _s['data'][2] is role:
                services.append(_s)

        return services

    def _get_connection(self, service):
        (host, port) = service['data']
        try:
            return rpyc.connect(host, port)
        except socket.error:
            raise Exception('Unable to connect to the follower')

    def exposed_register(self, host, port, role):
        data = (host, int(port), role)
        token = self._set_token(data.__str__())

        self.SERVICES[token] = {'data': data, 'connected': True,
                                'authenticate': False}

        logger.info('%s registration succeeded on address %s'
                    % (role, host + port))

        return token, ''

    def exposed_auth_service(self, token, owner, key):
        service = self.SERVICES[token]

        if service is None:
            return False, ('Could not find follower to authenticate. Is '
                           ' is registered ?')

        service['authenticate'] = {'owner': owner, 'key': key}

        logger.info('Follower %s successfully authenticated'
                    % (service.data.__str__()))

        return True, ''

    def forget(self, token):
        service = self.SERVICES[token]

        if service is None:
            return False, 'Could not find follower to forget'

        self.SERVICES[service] = None

        return True, ''

    # }}}
