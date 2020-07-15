#!/usr/bin/python

import os
import sys
import json
import random
import string
import logging

FORMAT = '%(asctime)s %(levelname)s %(message)s'


def load_configuration_file(conf_filepath):
    """ Load a configuration file with valid JSON format """
    conf = {}

    if not os.path.isfile(conf_filepath):
        print 'Invalid conf file %s' % conf_filepath
        sys.exit(0)

    with open(conf_filepath) as json_file:
        conf = json.load(json_file)

    return conf


def random_hex(length):
    """ Generate random string from HEX digits """
    return ''.join(random.choice(string.hexdigits) for i in range(length))


def get_logger_by_name(name=None):
    formatter = logging.Formatter(FORMAT)
    file_handler = logging.FileHandler('log/blockchain.log')
    file_handler.setFormatter(formatter)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)
    logger.setLevel(logging.DEBUG)

    return logger
