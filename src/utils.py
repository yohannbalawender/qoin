import os
import sys
import json

def load_configuration_file(conf_filepath):
    conf = {}

    if not os.path.isfile(conf_filepath):
        print 'Invalid conf file %s' % conf_filepath
        sys.exit(0)

    with open(conf_filepath) as json_file:
        conf = json.load(json_file)

    return conf
