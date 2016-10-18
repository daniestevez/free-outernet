#!/usr/bin/env python3
#
# Copyright 2016 Daniel Estevez <daniel@destevez.net>.
# 
# This is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3, or (at your option)
# any later version.
# 
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this software; see the file COPYING.  If not, write to
# the Free Software Foundation, Inc., 51 Franklin Street,
# Boston, MA 02110-1301, USA.


import kiss
import protocols
import timeservice
import files

import sys
import os
import getopt
import socket
import struct

UDP_PORT = 10000
# Use UDP_HOST = '0.0.0.0' if you want IPv4 only
UDP_HOST = '::'

BUFSIZE = 4096

opDefragmenter = protocols.OPDefragmenter()
router = protocols.LDPRouter()

groundstationMac = None
BROADCAST_MAC = b'\xff'*6
ETHERTYPE = b'\x8f\xff'

def printMac(mac):
    return ('%02x:'* 5 + '%02x') % struct.unpack('B'*6, mac)
    
def printEthertype(ethertype):
    return hex(struct.unpack('>H', ethertype)[0])

def processFrame(frame):
    global groundstationMac
    if len(frame) < 14:
        return
    srcmac = frame[6:12]
    dstmac = frame[:6]
    ethertype = frame[12:14]
    if dstmac != BROADCAST_MAC or ethertype != ETHERTYPE:
        print('Received interesting Ethernet frame with src MAC {}, dst MAC {} and ethertype {}'.format(printMac(srcmac), printMac(dstmac), printEthertype(ethertype)))
    if srcmac != groundstationMac:
        print('Receiving Ethernet frames from groundstation with MAC {}'.format(printMac(srcmac)))
        groundstationMac = srcmac
    try:
        packet = opDefragmenter.push(protocols.OP(frame[14:]))
    except ValueError:
        return
    if not packet:
        return
    try:
        packet = protocols.LDP(packet)
    except ValueError as e:
        print(e)
        return
    router.route(packet)

def getSocket():
    s = None
    for res in socket.getaddrinfo(UDP_HOST, UDP_PORT, socket.AF_UNSPEC, socket.SOCK_DGRAM, 0,
                   socket.AI_PASSIVE):
        af, socktype, proto, canonname, sa = res
        try:
            s = socket.socket(af, socktype, proto)
        except OSError as msg:
            print('Socket error', msg)
            continue
        try:
            s.bind(sa)
        except OSError as msg:
            print('Bind error', msg)
            s.close()
            continue
        break
    return s

def usage():
    print('Usage: {} [OPTIONS]'.format(sys.argv[0]))
    print('')
    print('By default, {} will listen on a UDP socket for Outernet frames'.format(sys.argv[0]))
    print('If you want to use a KISS file as input, you must use the -k option')
    print('')
    print('''Options:
\t-h, --help\t\tHelp
\t-o, --output=DIR\tDirectory to use to save files (defaults to the current directory)
\t-k, --kiss=FILE\t\tKISS file to use as input
\t-p, --port=PORT\t\tUDP port to listen (default {})
\t    --host=HOST\t\tUDP host to listen (default ::, use 0.0.0.0 for IPv4 only)
'''.format(UDP_PORT))
    

def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'ho:k:p:',
                                   ['help', 'output=', 'kiss=', 'port=', 'host='])
    except getopt.GetoptError as err:
        print(err)
        usage()
        sys.exit(1)
    output = os.getcwd()
    kissinput = None
    port = UDP_PORT
    host = UDP_HOST
    for o, a in opts:
        if o in ('-h', '--help'):
            usage()
            sys.exit()
        elif o in ('-o', '--output'):
            output = a
        elif o in ('-k', '--kiss'):
            kissinput = a
        elif o in ('-p', '--port'):
            if kissinput:
                print('UDP port cannot be used with KISS file input')
                usage()
                sys.exit(1)
            port = int(a)
        elif o == '--host':
            if kissinput:
                print('UDP host cannot be used with KISS file input')
                usage()
                sys.exit(1)
            host = a
        else:
            print('Invalid option')
            usage()
            sys.exit(1)

    timeservice.TimeService(router)
    files.FileService(router, output)
    
    if kissinput:
        kissFile = open(kissinput, 'rb')
        kissDeframer = kiss.KISSDeframer()
        frames = kissDeframer.push(kissFile.read())
        for frame in frames:
            processFrame(frame)
    else:
        s = getSocket()
        while True:
            try:
                frame = s.recv(BUFSIZE)
            except KeyboardInterrupt:
                print('')
                sys.exit()
            processFrame(frame)

if __name__ == '__main__':
    main()
