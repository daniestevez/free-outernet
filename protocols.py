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
# 

"""Outernet OP and LDP protocols"""

__author__ = 'Daniel Estevez'
__copyright__ = 'Copyright 2016, Daniel Estevez'
__license__ = 'GPLv3'
__maintainer__ = 'Daniel Estevez'
__email__ = 'daniel@destevez.net'


import struct

class OP:
    """
    Outernet Protocol (OP) packet

    OP is the L3 protocol of Outernet
    """
    __header_len = 6

    def __init__(self, data):
        """
        Create OP packet

        Returns a new OP packet
        Args:
          data (bytes): packet contents

        Throws ValueError if packet is malformed
        """
        
        header = data[:self.__header_len]
        if len(header) < self.__header_len:
            raise ValueError('Malformed OP packet: too short')
            
        self.length, self.fragmentation, self.unknown, \
          self.last_fragment, self.fragment_number = struct.unpack('>HccBB', header)
        self.payload = data[self.__header_len : self.__header_len + self.length - 4]

class OPDefragmenter:
    """
    OP defragmenter

    Performs defragmentation of OP packets. New packets can be pushed
    with .push(), which will return an L4 packet if defragmentation
    is successful
    """
    def __init__(self):
        """
        Initialize defragmenter
        """
        self.__payload = bytes()
        self.__last_fragment = -1
        self.__previous_fragment = -1

    def push(self, packet):
        """
        Push new packet into defragmenter

        Returns an the palyoad (bytes) if defragmentation is succesful,
        None otherwise

        Args:
          packet (OP): Packet to push
        """
        if packet.fragment_number != self.__previous_fragment + 1:
            # packet lost
            self.__init__()

        if packet.fragment_number == 0:
            # first fragment
            self.__init__()
            self.__last_fragment = packet.last_fragment
        
        if packet.last_fragment == self.__last_fragment and \
            packet.fragment_number == self.__previous_fragment + 1:
            # fragment ok
            self.__payload = self.__payload + packet.payload
            self.__previous_fragment = packet.fragment_number

        if self.__payload and self.__previous_fragment == self.__last_fragment:
            # packet complete
            payload = self.__payload
            self.__init__()
            return payload

class LDP:
    """
    Lightweight Datagram Protocol (LDP) packet

    LDP is the L4 protocol of Outernet
    """
    __header_len = 6
    __checksum_len = 4

    def __init__(self, data):
        """
        Create an LDP packet

        Returns a new LDP packet
        Args:
          data (bytes) : packet contents

        Throws ValueError if packet is malformed
        """
        if len(data) < self.__header_len + self.__checksum_len:
            raise ValueError('Malformed LDP packet: too short')
        header = data[:self.__header_len]
        self.checksum = data[-self.__checksum_len:]
        # TODO implement checksum handling

        self.a, self.length, self.b = struct.unpack('>HHH', header)
        self.payload = data[self.__header_len : -self.__checksum_len]
        if self.length != len(data):
            raise ValueError('Malformed LDP packet: length field mismatch')

class LDPRouter:
    """
    LDP router

    Sends an LDP packet to the appropriate function according to the
    a and b fields in the LDP packet. The packet handler functions
    are previously registered whith LDPRouter().register()
    """
    def __init__(self):
        """
        Create a new LDP router
        """
        self.__registrations = dict()
        
    def route(self, packet):
        """
        Push an LDP packet into the router, calling the appropriate
        packet handler function

        Args:
          packet (LDP): packet to route
        """
        key = (packet.a, packet.b)
        if key not in self.__registrations:
            print('Unknown routing for packet with a = {}, b = {}'.format(hex(packet.a), hex(packet.b)))
        else:
            self.__registrations[(packet.a, packet.b)](packet)

    def register(self, fun, a, b):
        """
        Register a packet handler

        Args:
          fun: packet handler function (it must take a single argument of type LDP)
          a: a value of the packets to handle
          b: b value of the packets to handle
        """
        self.__registrations[(a,b)] = fun
