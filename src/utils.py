#!/usr/bin/python

import os
import sys
import json
import random
import string
import logging

# Logging {{{

FORMAT = '%(asctime)s %(levelname)s %(message)s'

BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = range(30, 38)

RESET_SEQ = "\033[0m"
COLOR_SEQ = "\033[%d;21m"
BOLD_RED_SEQ = "\033[1;31m"

MAPPING = {
    'DEBUG': (COLOR_SEQ % BLUE) + FORMAT + RESET_SEQ,
    'INFO': (COLOR_SEQ % GREEN) + FORMAT + RESET_SEQ,
    'WARNING': (COLOR_SEQ % YELLOW) + FORMAT + RESET_SEQ,
    'ERROR': (COLOR_SEQ % RED) + FORMAT + RESET_SEQ,
    'CRITICAL': BOLD_RED_SEQ + FORMAT + RESET_SEQ
}

# }}}


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


class CustomFormatter(logging.Formatter):
    """Logging Formatter to add colors and count warning / errors"""

    def format(self, record):
        levelname = record.levelname
        fmt = MAPPING[levelname]
        formatter = logging.Formatter(fmt)

        return formatter.format(record)


def get_logger_by_name(name=None):
    file_handler = logging.FileHandler('log/blockchain.log')
    file_handler.setFormatter(CustomFormatter())

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(CustomFormatter())

    logger = logging.getLogger(name)
    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)
    logger.setLevel(logging.DEBUG)

    return logger
