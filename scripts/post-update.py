#!/usr/bin/python

import sys
import json
import subprocess
import requests
import json
import os

conf = {}

def send_notification(_data):
    data=json.dumps(_data)
    headers={'content-type':'application/json'}
    requests.post('%s/gerrit/notify' % conf['server'],
                  data=data, headers=headers)

def load_configuration_file(conf_filepath):
    global conf

    if not os.path.isfile(conf_filepath):
        print 'Invalid conf file %s' % conf_filepath
        sys.exit(0)

    with open(conf_filepath) as json_file:
        conf = json.load(json_file)

    conf['server'] = 'http://%s:%s' % (conf['server']['ip'],
                                       conf['server']['port'])

def main():
    load_configuration_file(os.path.join('src', 'confs', 'post-update.conf'))

    COMMIT_STR = subprocess.check_output(["git", "log", "-n 1", "--numstat",
                                          "--pretty=format:'%ae%n%s%n%ct'"])

    COMMIT = COMMIT_STR.splitlines()

    add = 0
    rem = 0

    for _str in COMMIT[2:]:
        substr = _str.split('\t')
        try:
            add += int(substr[0])
        except:
            pass

        try:
            rem += int(substr[1])
        except:
            pass

    data={
        'email': COMMIT[0][1:],
        'length': len(COMMIT[1]),
        'date': COMMIT[2],
        'nb_files': len(COMMIT[3:]),
        'nb_insertions': add,
        'nb_deletions': rem
    }

    send_notification(data)

main()
