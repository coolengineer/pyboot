#!/usr/bin/env python
#
# pyboot.py : Simple Diskless Boot Helper
# (C)Copyright by Hojin Choi <hojin.choi@gmail.com>
# 2018.07.19
# 2012.02.04

from __future__ import print_function

import argparse
import sys
import os
import select
import traceback
from pyboot_dhcpd import Dhcpd
from pyboot_tftpd import Tftpd
from pyboot_server import PybootException, PybootServer

_procname = sys.argv[0].split('/')[-1]

class PybootConfig:
    def __init__(self):
        self.ip = '0.0.0.0'

class Pyboot(PybootServer):
    def __init__(self):
        super(Pyboot, self).__init__()
        self.config = PybootConfig()

    def init(self, config):
        self.config = config

    def run(self):
        try:
            dhcpd = Dhcpd()
            tftpd = Tftpd()
            dhcpd.init(self.config)
            tftpd.init(self.config)
            print('')

            while True:
                rlist = [ dhcpd.sock, tftpd.sock ]
                wlist = []
                elist = []
                ( rlist, wlist, elist ) = select.select( rlist, wlist, elist )
                for sock in rlist:
                    if sock == dhcpd.sock:
                        dhcpd.serve()
                    if sock == tftpd.sock:
                        tftpd.serve()
        except KeyboardInterrupt as e:
            print("\nBye!")
        except PybootException as e:
            print(str.join('\n', map(lambda line: 'ERROR: %s: %s' % (_procname, line), e[1].split('\n') )))
            sys.exit(e[0])
        except Exception as e:
            traceback.print_exc()

if __name__ == '__main__':
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument('-a', '--ip',        metavar='<ip address>', help='Client IP address    (default: 192.168.0.99)')
        parser.add_argument('-m', '--mask',      metavar='<netmask>',    help='Netmask              (default: 255.255.255.0)')
        parser.add_argument('-g', '--gateway',   metavar='<ip address>', help='Gateway/Router IP    (default: 192.168.0.1)')
        parser.add_argument('-b', '--bindip',    metavar='<ip address>', help='My ip address to use (default: 0.0.0.0)')
        parser.add_argument('--domain',          metavar='<domain>',     help='Domain name          (default: localdomain)')
        parser.add_argument('-d', '--dns',       metavar='<ip address>', help='DNS ip address       (default: Gateway IP)')
        parser.add_argument('--tftp',            metavar='<ip address>', help='Tftp server IP       (default: Gateway IP)')
        parser.add_argument('--boot',            metavar='<file name>',  help='Tftp boot file       (default: "/pxelinux.0")')
        parser.add_argument('-t', '--tftproot',  metavar='<path>',       help='Tftp root directory  (default: "./tftproot")')
        parser.add_argument('-i', '--interface', metavar='<interface>',  help='Network interface    (e.g. eth0, en0, bridge001,...)')
        parser.add_argument('-l', '--list', action='store_const', const=1, help='List network interfaces')
        config = parser.parse_args()
        if config.list:
            PybootServer().detect_interfaces()
            sys.exit(0)
        pyboot = Pyboot()
        pyboot.init(config)
        pyboot.run()
    except Exception as e:
        traceback.print_exc()
        sys.exit(1)

