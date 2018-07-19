#!/usr/bin/env python
#
# pyboot_server.py : Daemon Base Class
# (C)Copyright by Hojin Choi <hojin.choi@gmail.com>
# 2018.07.19

from __future__ import print_function

import os
import sys
import socket
import errno
import struct
import traceback
import fcntl

class PybootException(Exception):
    pass

class PybootServer(object):

    def __init__(self):
        self.sock = -1
        self.bindip = '0.0.0.0'
        self.netmask = '255.255.255.0'
        self.broadcast = '192.168.0.255'
        self.gateway = '192.168.0.1'

    def init(self, config):
        self.config = config

        self.detect_from_interface()

        self.bindip = config.bindip or self.bindip
        self.ipaddr = config.ip or self.ipaddr
        self.netmask = config.mask or self.netmask
        self.broadcast = PybootServer.int2ip(PybootServer.ip2int(self.bindip) | (~PybootServer.ip2int(self.netmask) & 0xffffffff))
        self.gateway = config.gateway or self.gateway

    def detect_from_interface(self):
        if not self.config.interface:
            return False

        device = self.config.interface
        uname =  os.uname()[0]

        if uname == 'Linux':
            SIOCGIFADDR = 0x8915
            SIOCGIFBRDADDR = 0x8919
            SIOCGIFNETMASK = 0x891b
        elif uname == 'Darwin':
            SIOCGIFADDR = 0xc0206921
            SIOCGIFBRDADDR = 0xc0206923
            SIOCGIFNETMASK = 0xc0206925
        else:
            raise PybootException(1, 'pyboot_server.py: Not supported OS, You can research the values for setsockopt')

        ifreq = struct.pack('16sH14s', device, socket.AF_INET, '\x00'*14)
        if self.sock == -1:
            print("I make a socket for detecting")
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sockfd = self.sock.fileno()

        fmt = '%d.%d.%d.%d'

        res = fcntl.ioctl(sockfd, SIOCGIFADDR, ifreq)
        self.bindip = fmt % struct.unpack('16x4x4B8x', res)
        if self.config.bindip and self.bindip != self.config.bindip:
            raise PybootException(2, 'You specified both bind ip (-b, --bindip) and interface (-i, --interface), but the values are different.\nUse just one option')

        res = fcntl.ioctl(sockfd, SIOCGIFNETMASK, ifreq)
        self.netmask = fmt % struct.unpack('16x4x4B8x', res)
        self.ipaddr = PybootServer.int2ip(PybootServer.ip2int(self.bindip) + 1)
        self.gateway = self.bindip
        return True

    @classmethod
    def ip2int(cls, addr):
        return struct.unpack("!I", socket.inet_aton(addr))[0]

    @classmethod
    def int2ip(cls, addr):
        return socket.inet_ntoa(struct.pack("!I", addr))

    @classmethod
    def errorlog(msg, *vargs):
        nv = [x for x in vargs]
        print('Error:', msg, str.join(' ', nv))

