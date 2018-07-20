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
import array

class PybootException(Exception):
    pass

class PybootServer(object):

    def __init__(self):
        self.sock = -1
        self.bindip = '192.168.0.1'
        self.ipaddr = '192.168.0.10'
        self.netmask = '255.255.255.0'
        self.broadcast = '192.168.0.255'
        self.gateway = '192.168.0.1'

    def init(self, config):
        self.config = config

        if not self.detect_from_interface():
            (device, ipaddr) = self.detect_interfaces(False)
            print("interface: %s" % device)
            self.detect_from_interface(device)

        self.bindip = config.bindip or self.bindip
        self.ipaddr = config.ip or self.ipaddr
        self.netmask = config.mask or self.netmask
        self.broadcast = PybootServer.int2ip(PybootServer.ip2int(self.bindip) | (~PybootServer.ip2int(self.netmask) & 0xffffffff))
        self.gateway = config.gateway or self.gateway

    def detect_from_interface(self, device=None):
        device = device or self.config.interface
        if not device:
            return False

        uname =  os.uname()[0]

        if uname == 'Linux':
            SIOCGIFADDR    = 0x8915
            SIOCGIFBRDADDR = 0x8919
            SIOCGIFNETMASK = 0x891b
        elif uname == 'Darwin':
            SIOCGIFADDR    = 0xc0206921
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

    def detect_interfaces(self, show=True):
        uname =  os.uname()[0]

        max_devices = 32
        if uname == 'Linux':
            SIOCGIFCONF = 0x8912
            ifsize = 40
            packfmt = '=iQ'
        elif uname == 'Darwin':
            SIOCGIFCONF = 0xc00c6924
            ifsize = 32
            packfmt = '=iQ'
        else:
            raise PybootException(1, 'pyboot_server.py: Not supported OS, You can research the values for setsockopt')

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sockfd = sock.fileno()

        max_bytes = 20 * ifsize
        #Make a buffer
        buff = array.array('B', '\0' * (max_devices * ifsize))
        #Get pointer and length of the buffer
        info = buff.buffer_info()
        #Make ioctl request info
        ifreq = struct.pack(packfmt, info[1], info[0])
        info = fcntl.ioctl(sockfd, SIOCGIFCONF, ifreq)
        #Parse return value
        info = struct.unpack(packfmt, info)
        #Convert return buffer to string
        buff = buff.tostring()

        devices = []
        pos = 0
        retaddr = None
        while pos < info[0]:
            #device name length is assumed as 16 bytes
            #the first octect is the length of each items
            #the second octect is the address family of each items
            device, length, family, addr = struct.unpack('16sBBxx4s', buff[pos:pos+24])
            if family == socket.AF_INET:
                device = device.split('\0')[0]
                devices.append(device)
                ipaddr, = struct.unpack('!I', addr)
                addr = socket.inet_ntoa(addr)
                if ipaddr / 0x1000000 == 0x7f:
                    if retaddr is None:
                        retaddr = (device, addr)
                else:
                    retaddr = (device, addr)
                if show:
                    print(device, addr)
            pos += 16 + length
        sock.close()
        return retaddr

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

