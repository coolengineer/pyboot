#!/usr/bin/env python

#
# pyboot_tftpd.py : Readonly TFTP Server daemon
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

class TftpContext:

    contexts = {}

    def __init__(self, config, remote):
        self.config = config
        self.remote = remote
        self.blksize = 512
        self.blknum = 1
        self.file = None
        self.filename = ''
        self.filesize = 0
        self.oack = ''

    @classmethod
    def get(cls, config, remote):
        if remote in cls.contexts:
            return cls.contexts[remote]
        context = TftpContext(config, remote)
        cls.contexts[remote] = context
        return context

    @classmethod
    def remove(cls, remote):
        if remote in cls.contexts:
            del cls.contexts[remote]

    def set_filename(self, filename):
        self.filename = filename
        if self.filename[0:1] == '/':
            self.filename = self.filename[1:]
        self.filename = '%s/%s' % (self.config.tftproot, self.filename )
        try:
            self.file = open( self.filename )
            self.file.seek(0, os.SEEK_END)
            self.filesize = self.file.tell()
            self.file.seek(0, os.SEEK_SET)
        except IOError as e:
            #Error
            self.file = None

class TftpPacket:
    TFTP_RRQ   = 1
    TFTP_WRQ   = 2
    TFTP_DATA  = 3
    TFTP_ACK   = 4
    TFTP_ERROR = 5
    TFTP_OACK  = 6
    config = {}

    def __init__(self, packet):
        ( self.opcode, ) = struct.unpack( '!H', packet[0:2] )
        self.packet = packet

    def parse(self, ctx):
        args = []
        if self.opcode == TftpPacket.TFTP_RRQ:
            args = self.packet[2:].split('\0')
            ctx.set_filename(args.pop(0))
        elif self.opcode == TftpPacket.TFTP_WRQ:
            args = self.packet[2:].split( '\0' )
            ctx.set_filename(args.pop(0))
            return
        elif self.opcode == TftpPacket.TFTP_ACK:
            ( blknum, ) = struct.unpack( '!H', self.packet[2:4] )
            ctx.blknum = blknum

        while len(args):
            opt = args.pop(0)
            arg = 0
            if opt == 'octet' or opt == 'netascii':
                ctx.mode = opt
                continue
            elif opt == 'blksize':
                ctx.blksize = int(args.pop(0))
                ctx.oack += opt + chr(0) + ('%d' % ctx.blksize) + chr(0)
            elif opt == 'tsize':
                if self.opcode == TftpPacket.TFTP_RRQ:
                    ctx.oack += opt + chr(0) + ('%d' % ctx.filesize) + chr(0)
                else:
                    ctx.filesize  = int(args.pop(0))

class TftpError:
    ERR_UNDEF      = 0         # Not defined, see error message (if any).
    ERR_NOTFOUND   = 1         # File not found.
    ERR_EACCESS    = 2         # Access violation.
    ERR_DISKFULL   = 3         # Disk full or allocation exceeded.
    ERR_ILLOPER    = 4         # Illegal TFTP operation.
    ERR_UNKNOWNTID = 5         # Unknown transfer ID.
    ERR_FILEEXIST  = 6         # File already exists.
    ERR_NOSUCHUSER = 7         # No such user.

    msg = {
        ERR_UNDEF      : 'Unknown',
        ERR_NOTFOUND   : 'File not found',
        ERR_EACCESS    : 'Access violation.',
        ERR_DISKFULL   : 'Disk full or allocation exceeded.',
        ERR_ILLOPER    : 'Illegal TFTP operation.',
        ERR_UNKNOWNTID : 'Unknown transfer ID.',
        ERR_FILEEXIST  : 'File already exists.',
        ERR_NOSUCHUSER : 'No such user.'
    }

    @classmethod
    def get(cls, code):
        return struct.pack('!HH', TftpPacket.TFTP_ERROR, code) + cls.msg[code]

class Tftpd(PybootServer):
    config_keys = ( 'TFTPROOT', 'TFTPDBINDADDR' )

    def __init__(self):
        super(Tftpd,self).__init__()
        self.tftproot = './tftproot'

    def init(self, config):
        try:
            self.sock = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )
            super(Tftpd,self).init(config)
            self.contexts = {}
            self.sock.bind( ('0.0.0.0',69) )
            self.tftproot = config.tftproot or self.tftproot
            print('tftpd: bind:', self.bindip)
            print('tftpd: root:', self.tftproot)

        except socket.error, e:
            if e[0] == socket.errno.EACCES:
                raise PybootException(10, 'Run again with root privilege')
            else:
                raise e

    def socket(self):
        return self.sock

    def recvfrom(self, length):
        return self.sock.recvfrom(length)

    def sendto(self, contents, remote):
        return self.sock.sendto(contents,remote)

    def tftp_connection( self, packet ):
        return { 1: 1 }

    def transmit_file(self, ctx):
        pos     = ctx.blksize * (ctx.blknum - 1)
        content = ''
        eof = False

        try:
            #Do nothing if far from the eof
            if pos > ctx.filesize:
                return
            ctx.file.seek( pos )

            opcode  = TftpPacket.TFTP_DATA
            content = ctx.file.read( ctx.blksize )
            arg = ctx.blknum
            #print('tftpd: Sending up to %d bytes' % ( pos + len(content) ))
            if ctx.blknum % 400 == 0:
                print('')
            elif ctx.blknum % 4 == 0:
                print('.', end='')
            if len(content) != ctx.blksize:
                eof = True
        except Exception as e:
            traceback.print_exc()
            opcode = TftpPacket.TFTP_ERROR
            content = 'File not found'
            arg = 1

        packet = struct.pack('!HH', opcode, arg )
        packet += content

        self.sendto( packet, ctx.remote )

        if eof:
            ctx.file.close()
            TftpContext.remove(ctx.remote)
            if ctx.filesize >= ctx.blksize:
                print('')

    def serve(self):
        (packet, remote) = self.recvfrom(65536)
        ctx = TftpContext.get(self, remote)
        packet = TftpPacket(packet)
        packet.parse(ctx)
        if packet.opcode == TftpPacket.TFTP_RRQ:
            if not ctx.file:
                print('tftpd: Read request: %s (file not found)' % ctx.filename)
                self.sendto( TftpError.get( TftpError.ERR_NOTFOUND ), remote )
                return
            else:
                print('tftpd: Read request: %s (filesize: %d)' % (ctx.filename, ctx.filesize))
            self.sendto( struct.pack('!H', TftpPacket.TFTP_OACK) + ctx.oack, remote )
            #self.transmit_file(ctx)
        elif packet.opcode == TftpPacket.TFTP_WRQ:
            self.sendto( TftpError.get(TftpError.ERR_EACCESS), remote )
        elif packet.opcode == TftpPacket.TFTP_ERROR:
            TftpContext.remove(remote)
        elif packet.opcode == TftpPacket.TFTP_ACK:
            #print('tftpd: Ack received: blknum %d' % ctx.blknum)
            ctx.blknum += 1
            self.transmit_file(ctx)

