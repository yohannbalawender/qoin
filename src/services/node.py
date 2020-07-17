#!/usr/bin/python

import socket
import hashlib

from src.utils import get_logger_by_name

import rpyc
from rpyc.utils.server import ThreadedServer

# {{{ Loggers

logger = get_logger_by_name('node')

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

        def _retry_wrapper(nb):
            while nb:
                try:
                    return fn(*args, **kwargs)
                except BaseException as e:
                    logger.warning('Exception occurred on %s (%s), '
                                   'retrying...' % (fn, e))
                    nb -= 1
                    pass

            logger.error('Too much exception, stop to retry')
            raise e

        return _retry_wrapper(nb)


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

    def register(self, conf):
        """
            A method used to register the follower on the leader
        """

        if self.leader_host is None or self.leader_port is None:
            raise BaseException('Cannot register on an unknown leader')

        if self.role is None:
            raise BaseException('Cannot register to the leader with an '
                                'unknown role')

        conn = self._get_connection()

        res, error = conn.root.register(socket.gethostname(), conf['port'],
                                        self.role)

        if not res:
            raise BaseException('Failed to register the follower: %s'
                                % (error))

        logger.info('%s successfully registered' % self.node_name)

        return res

    def authenticate(self, token, owner, key):
        """
            A method used to authenticate a follower to the leader
        """

        conn = self._get_connection()

        return conn.root.auth_service(token, owner, key)

    def _get_connection(self):
        """
            A method used to connect to the leader. Host and port must be
            defined before
        """

        try:
            return rpyc.connect(self.leader_host, self.leader_port)
        except socket.error:
            raise Exception('Unable to connect to the leader')


class FollowerService(rpyc.Service):
    def on_delog(self):
        """
            Child should override this method
        """
        logger.info('Follower on delogging called')

    def exposed_delog(self):
        logger.info('Leader has asked to delog. Good bye !')

        self.on_delog()

        return True, 200


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
            raise Exception('Unable to connect to the server')

    def exposed_register(self, host, port, role):
        data = (host, int(port), role)
        token = self._set_token(data.__str__())

        self.SERVICES[token] = {'data': data, 'authenticate': False}

        logger.info('%s registration succeeded on address %s'
                    % (role, (host + ':' + str(port))))

        return token, 200

    def exposed_auth_service(self, token, owner, key):
        service = self.SERVICES[token]

        if service is None:
            return False, 400, ('Could not find follower to authenticate. Is '
                                'it registered ?')

        # Check if the service is not already registered
        for k, s in self.SERVICES.iteritems():
            if not s['authenticate']:
                continue

            auth = s['authenticate']

            if auth['owner'] == owner and auth['key'] == key:
                return False, 400, 'Service is already registered'

        service['authenticate'] = {'owner': owner, 'key': key}

        logger.info('Follower %s successfully authenticated'
                    % (service['data'].__str__()))

        return True, 200, ''

    def forget(self, token):
        service = self.SERVICES.pop(token)

        if service is None:
            return False, 'Could not find follower to forget'

        try:
            host = service['data'][0]
            port = service['data'][1]

            conn = rpyc.connect(host, port)

            conn.root.delog()

            logger.info('Service %s delogged' % service['data'].__str__())
        except socket.error:
            # Could not connect to the follower
            pass

        return True, 200

    # }}}
