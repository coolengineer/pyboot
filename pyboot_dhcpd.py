#!/usr/bin/env python

#
# pyboot_dhcpd.py : Simple DHCP Daemon
# (C)Copyright by Hojin Choi <hojin.choi@gmail.com>
# 2018.07.19
# 2012.02.04
from __future__ import print_function

import os
import sys
import socket
import errno
import struct
import traceback
from pyboot_server import PybootException, PybootServer

MAGIC_COOKIE = 0x63825363
class OPTIONS:
    NETMASK      = 0x1
    TIMEOFFSET   = 0x2
    GATEWAY      = 0x3
    TIMESERVER   = 0x4
    DNS          = 0x5
    DNS2         = 0x6
    RLPSERVER    = 11
    HOSTNAME     = 12
    BOOTFILESIZE = 13
    DOMAIN       = 15
    SWAPSERVER   = 16
    ROOTPATH     = 17
    EXTENSIONFILE = 18
    BROADCASTADDR= 28
    DHCPMSGTYPE  = 53
    DHCPOPTIONS  = 55
    DHCPMAXMSG   = 57
    BOOTFILE     = 67
    GUID         = 97
    NEXTSERVER   = 128
    PROXYURL     = 252

    @classmethod
    def getname(cls, val):
        for k in dir(cls):
            if hasattr(cls, k) and getattr(cls, k) == val:
                return k
        return ''

class OPTYPE:
    REQUEST      = 0x1
    RESPONSE     = 0x2

# DHCP Options: http://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.txt
class DhcpPacket(dict):
    def __init__(self, packet, remote = None):
        self.remote = remote
        (
            self.op, self.htype, self.hlen, self.hops, 
            self.xid,
            self.secs, self.flags,
            self.ciaddr,
            self.yiaddr,
            self.siaddr,
            self.giaddr,
            self.chaddr
        ) = struct.unpack( '!BBBBLHH4s4s4s4s16s', packet[0:44] )
        self.remoteaddr = '%02x:%02x:%02x:%02x:%02x:%02x' % (
                ord(self.chaddr[0]), ord(self.chaddr[1]), ord(self.chaddr[2]),
                ord(self.chaddr[3]), ord(self.chaddr[4]), ord(self.chaddr[5]) )
        self.rawoptions = packet[240:]

    def __getattr__(self, key):
        if key in self:
            return self[key]
        return None

    def __setattr__(self, key, value):
        self[key] = value

    def parse(self):
        self.options = {}
        self.parsed_options = {}
        i = 0
        option_len = len(self.rawoptions)
        while i < option_len:
            opt = ord(self.rawoptions[i])
            if opt == 0xff:
                break
            size = ord(self.rawoptions[i+1])
            value = self.rawoptions[i+2:i+2+size]
            self.options[opt] = value
            i = i + 2 + size
            if opt == OPTIONS.GUID:
                #print(tuple( ord(i) for i in list(value) ))
                self.GUID = '%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X' % tuple( ord(i) for i in list(value[1:]) )
                self.UID  = '%02X%02X%02X%02X' % tuple( ord(i) for i in list(value[1:5]) )

    def dump(self):
        print('GUID: ', self.GUID)
        required1 = []
        required2 = []
        if OPTIONS.DHCPOPTIONS in self.options:
            for opt in self.options[OPTIONS.DHCPOPTIONS]:
                opt = ord(opt)
                name = OPTIONS.getname(opt)
                if name:
                    required1.append(name)
                else:
                    required2.append(str(opt))
            print('Required: %s %s' % (str.join(' ', required1), str.join(' ', required2)))

class Dhcpd(PybootServer):
    sock = None
    config = {}

    def __init__(self):
        super(Dhcpd,self).__init__()
        self.ipaddr = '192.168.0.99'
        self.dns = self.gateway
        self.tftp = self.gateway
        self.domain = 'localdomain'
        self.bootfile = '/pxelinux.0'
        self.proxyurl = ''

    def init(self, config):
        try:
            self.sock = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )
            super(Dhcpd,self).init(config)
            self.dns = config.dns or self.bindip
            self.tftp = config.tftp or self.bindip
            self.domain = config.domain or self.domain
            self.bootfile = config.boot or self.bootfile

            #self.sock.bind( (self.bindip,67) ) #Do not use bindp to bind, but to determine broadcast address
            self.sock.bind( ('0.0.0.0',67) )
            self.sock.setsockopt( socket.SOL_SOCKET, socket.SO_BROADCAST, 1 )

            print('dhcpd: bind:', self.bindip)
            print('dhcpd: client ip:', self.ipaddr)
            print('dhcpd: netmask:', self.netmask)
            print('dhcpd: broadcast:', self.broadcast)
            print('dhcpd: gateway:', self.gateway)
            print('dhcpd: dns:', self.dns)
            print('dhcpd: tftp:', self.tftp)
            print('dhcpd: domain:', self.domain)
            print('dhcpd: bootfile:', self.bootfile)
        except socket.error as e:
            if e[0] == socket.errno.EACCES:
                raise PybootException(10, 'Run again with root privilege')
            else:
                raise e

    def recvfrom(self, length):
        return self.sock.recvfrom(length)

    def sendto(self, contents, remote):
        return self.sock.sendto(contents, 0, remote)

    def get_response(self, req ):
        r = ''
        logs = []
        try:
            for opt in req.options[OPTIONS.DHCPOPTIONS]:
                opt = ord(opt)
                #print 'Option ', opt
                response = self.response_option( req, opt, logs )
                r = r + response
            r += chr(0xff)
            print('> DHCP Response packet send')
            print(str.join('\n', logs))

        except KeyError as e:
            print('Required option ommitted.', e)
            return None

        return struct.pack( '!BBBBLHH4s4s4s4s16s192sL308s', 2, 1, 6, 0, req.xid, req.secs, 0,
            socket.inet_aton( self.ipaddr ),
            socket.inet_aton( self.ipaddr ),
            socket.inet_aton( self.tftp ),
            socket.inet_aton( self.tftp ),
            (req.chaddr + chr(0) * 16 )[0:16],
            chr(0) * 192,
            MAGIC_COOKIE,
            (r + chr(0) * 308)[0:308]
        )

    def serve_request(self, req):
        print('* DHCP Request packet received from %s' % (req.remoteaddr))
        req.parse()
        req.dump()
        response = self.get_response( req )
        if response:
            self.sendto( response, (self.broadcast, 68) )
        print('')

    def serve(self):
        (packet, remote) = self.recvfrom(65536)
        try:
            req = DhcpPacket(packet, remote)
            if req.op == OPTYPE.REQUEST:
                self.serve_request(req)
            else:
                print('* DHCP packet received from %s: optype(%d) discarded' % (remote, req.op))
                return
        except Exception as e:
            traceback.print_exc()

    def response_option( self, req, opt, logs ):
        response = chr(opt)
        value = ''
        if opt == OPTIONS.NETMASK:
            logs += ['Subnet: ' + self.netmask]
            value = struct.pack( '4s', socket.inet_aton( self.netmask ) )
        elif opt == OPTIONS.GATEWAY:
            logs += ['Router: ' + self.gateway]
            value = struct.pack( '4s', socket.inet_aton( self.gateway ) )
        elif opt == OPTIONS.DNS:
            logs += ['Dns1: ' + self.dns]
            value = struct.pack( '4s', socket.inet_aton( self.dns ) )
        elif opt == OPTIONS.DNS2:
            logs += ['Dns2: ' + self.dns]
            value = struct.pack( '4s', socket.inet_aton( self.dns ) )
        elif opt == OPTIONS.HOSTNAME:
            hostname = 'host-' + req.remoteaddr.replace(':', '')[-6:]
            logs += ['Hostname: ' + hostname]
            value = hostname
        elif opt == OPTIONS.DOMAIN:
            logs += ['Domain: ' + self.domain]
            value = self.domain
        elif opt == OPTIONS.BOOTFILE:
            logs += ['Boot file: ' + self.bootfile]
            value = self.bootfile
        elif opt == OPTIONS.BROADCASTADDR:
            logs += ['Broadcast Address: ' + self.broadcast]
            value = struct.pack( '4s', socket.inet_aton( self.broadcast ) )
        elif opt == OPTIONS.NEXTSERVER:
            logs += ['TFT Server: ' + self.tftp]
            value = struct.pack( '4s', socket.inet_aton( self.tftp ) )
        elif opt == OPTIONS.PROXYURL:
            logs += ['Proxy: ' + self.proxyurl]
            if self.proxyurl:
                value = self.proxyurl
            else:
                value = ''
        else:
            return ''

        response += chr( len(value) ) + value
        return response


