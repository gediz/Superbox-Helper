#!/usr/bin/python3

import argparse
import logging as log
from time import time_ns
import requests

p_desc = 'Automates some basic functionality of Turkcell Superbox'
p_fmt = argparse.ArgumentDefaultsHelpFormatter

parser = argparse.ArgumentParser(description=p_desc, formatter_class=p_fmt)
parser.add_argument('router_ip', nargs='?', default='192.168.1.1',
                    help='IP address of the gateway')
parser.add_argument('username', nargs='?', default='admin',
                    help='user name to be used for authentication')
parser.add_argument('password',
                    help='password to be used for authentication')
parser.add_argument('--verbose', '-v', action='count', default=0)

args = parser.parse_args()

# https://patorjk.com/software/taag/#p=display&h=3&v=3&f=Slant
art = r'''
   _____                       __
  / ___/__  ______  ___  _____/ /_  ____  _  __
  \__ \/ / / / __ \/ _ \/ ___/ __ \/ __ \| |/_/
 ___/ / /_/ / /_/ /  __/ /  / /_/ / /_/ _>  <
/_____\____/ .___/\___/_/  /_.___/\____/_/|_|
   / / / _/_/ / /___  ___  _____
  / /_/ / _ \/ / __ \/ _ \/ ___/
 / __  /  __/ / /_/ /  __/ /
/_/ /_/\___/_/ .___/\___/_/  v0.1
            /_/
'''


class Superbox:
    def __init__(self, ip_, username_, password_, verbose_: bool):
        self.ip = ip_
        self.user = username_
        self.pw = password_
        self.verbose = verbose_

        if (self.verbose):
            log.basicConfig(
                format='[%(levelname)s] %(message)s', level=log.INFO)
            self.print_input_args()
        else:
            log.basicConfig(format='[%(levelname)s] %(message)s')

        self.initiate_session()
        self.authenticate()

    def print_input_args(self):
        print(art)
        log.info('Input arguments')
        log.info('\tRouter IP: {}'.format(self.ip))
        log.info('\tUsername: {}'.format(self.user))
        log.info('\tPassword: {}'.format(self.pw))

    def initiate_session(self):
        '''Initiate a requests session and execute a basic test.'''
        self.login_cookie = None
        self.router_URL = 'http://{}'.format(self.ip)

        self.s = requests.Session()

        # a dumb way to test connection
        r = self.s.get(self.router_URL)
        r.raise_for_status()

    def get_epoch(self):
        return(int(time_ns() / 1000000))

    def get_cmd(self, cmd, *cmds):
        # router return empty response for some parameters
        # when Referer is omitted from the headers
        self.s.headers.update(
            {'Referer': 'http://{}/index.html'.format(self.ip)})

        # concatenate commands into one variable if there's
        # more than one and 'multi_data' parameter should be
        # set to '1' when multiple values are requested.
        multi_data = None
        if cmds:
            multi_data = '1'
            cmd += ',{}'.format(','.join(cmds))

        # 'isTest' and '_' parameters were always present while sending
        # a cmd request so I thought it's better to include them
        payload = {'isTest': 'false', '_': self.get_epoch(),
                   'multi_data': multi_data, 'cmd': cmd}
        r = self.s.get('http://{}/goform/goform_get_cmd_process'.format(self.ip),
                       params=payload)

        json_response = r.json()

        if json_response:
            log.info('get_cmd()')
            for command in cmd.split(','):
                log.info('\t{}: {}'.format(command, json_response[command]))

        return(json_response)

    def authenticate(self):
        '''Do the authentication'''
        self.login_cookie = None
        self.router_URL = 'http://{}'.format(self.ip)

        self.s = requests.Session()

        r = self.s.get(self.router_URL)
        r.raise_for_status()




superbox = Superbox(args.router_ip, args.username, args.password, args.verbose)

if __name__ == '__main__':
    print('hello?')
