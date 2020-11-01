#!/usr/bin/python3

import argparse
import logging as log
from time import time_ns
import requests
from hashlib import md5
from base64 import b64encode

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
        log.info('Test connection by fetching router index page...')
        r = self.s.get(self.router_URL)

        if r.status_code == requests.codes.ok:
            log.info('Successfully fetched index page of the router.')
        else:
            log.error('Could not get index page of the router.')

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
        # a cmd request so I thought it's better to include them. removing
        # them did no harm but I do not want any surprise happen.
        payload = {'isTest': 'false', '_': self.get_epoch(),
                   'multi_data': multi_data, 'cmd': cmd}
        r = self.s.get('http://{}/goform/goform_get_cmd_process'.format(self.ip),
                       params=payload)

        json_response = r.json()

        if json_response:
            log.info('get_cmd()')
            for command in cmd.split(','):
                log.info('\t{}: {}'.format(command, json_response[command]))

        if multi_data:
            return(json_response)
        else:
            # no need send a json object when only one parameter is requested
            return(json_response[cmd])

    def compose_AD(self):
        '''Calculate AD digest after retrieving the required parameters'''
        params = self.get_cmd('RD', 'wa_inner_version', 'cr_version')

        RD = params['RD']
        rd0 = params['wa_inner_version']
        rd1 = params['cr_version']

        log.info('Get required parameters and compose AD digest...')

        rd = rd0 + rd1

        rd_md5 = md5(rd.encode()).hexdigest()
        ad = rd_md5 + RD
        AD = md5(ad.encode()).hexdigest()

        return(AD)

    def authenticate(self):
        '''Do the authentication'''
        self.AD = self.compose_AD()

        self.s.headers.update(
            {'Referer': 'http://{}/index.html'.format(self.ip),
             'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'})

        pw_b64 = b64encode(self.pw.encode()).decode()

        payload = {'isTest': 'false', 'goformId': 'LOGIN_MULTI_USER',
                   'user': self.user, 'password': pw_b64, 'AD': self.AD}
        r = self.s.post('http://{}/goform/goform_set_cmd_process'.format(self.ip),
                        data=payload)

        auth_result = r.json()['result']
        return(auth_result)


superbox = Superbox(args.router_ip, args.username, args.password, args.verbose)

if __name__ == '__main__':
    print('hello?')
