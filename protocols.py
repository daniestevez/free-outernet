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
import zfec
from crcmod.predefined import PredefinedCrc

class OP:
    """
    Outernet Protocol (OP) packet

    OP is the L3 protocol of Outernet
    """
    __header_len = 5

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

        self.length, self.fragment_type, self.carousel_id, \
          self.last_fragment, self.fragment_index = struct.unpack('>BBBBB', header)
        self.payload = data[self.__header_len : self.__header_len + self.length - 4]

class PartialLDP:
    """
    Fragmented LDP packet

    A LDP packet which has not yet been completely received.
    """
    def __init__(self):
        self.reset()

    """
    Reset the internal state
    """
    def reset(self):
        self.__fragments = {}
        self.__frag_recv = 0
        self.__fec_recv = 0
        self.frag_size = None
        self.frag_count = None
        self.fec_count = None
        self.next_index = 0

    """
    Push a data block

    Args:
      index (int): the index of the fragment
      payload (bytes): the actual data
    """
    def push_data(self, index, payload):
        if index in self.__fragments:
            return
        self.__fragments[index] = payload
        self.__frag_recv += 1

    """
    Push a FEC block

    Args:
      index (int): the index of the FEC block
      payload (bytes): the actual FEC data
    """
    def push_fec(self, index, payload):
        if not self.frag_count or (self.frag_count + index) in self.__fragments:
            return
        self.__fragments[self.frag_count + index] = payload
        self.__fec_recv += 1

    """
    Indicates whether a reconstruction is possible
    """
    @property
    def complete(self):
        return self.frag_count and self.__fec_recv + self.__frag_recv >= self.frag_count

    """
    Decode the packet
    """
    def decode(self):
        if self.__frag_recv == self.frag_count: # No error FEC decoding necessary
            return b''.join([self.__fragments[s] for s in range(self.frag_count)])
        k = self.frag_count
        n = k + self.fec_count
        decoder = zfec.Decoder(k, n)
        sharenums = list(self.__fragments.keys())
        if len(sharenums) != k:
            print("[ERROR] Unexpected number of fragments. k = {}, sharenums = {}".format(k, sharenums))
            return
        return b''.join(decoder.decode([self.__fragments[s] for s in sharenums], sharenums))

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
        self.__pending = {}

    def push(self, packet):
        """
        Push new packet into defragmenter

        Returns a payload (bytes) if defragmentation is succesful,
        None otherwise

        Args:
          packet (OP): Packet to push
        """
        ldp = self.__pending.get(packet.carousel_id)
        if not ldp:
            ldp = PartialLDP()
            self.__pending[packet.carousel_id] = ldp

        if packet.fragment_type == 0x3c or packet.fragment_type == 0xc3:
            if packet.fragment_type == 0x3c and packet.fragment_index == 0: # TODO Verify correctness
                return packet.payload
            if packet.fragment_index < ldp.next_index:
                ldp.reset()
            if not ldp.frag_size:
                ldp.frag_size = packet.length - 4
            if not ldp.frag_count:
                ldp.frag_count = packet.last_fragment + 1
            ldp.next_index = packet.fragment_index + 1
            ldp.push_data(packet.fragment_index, packet.payload)
            if packet.fragment_type == 0x3c and ldp.complete:
                decoded = ldp.decode()
                ldp.reset()
                return decoded
        elif packet.fragment_type == 0x69:
            if not ldp.frag_size:
                return
            if not ldp.fec_count:
                ldp.fec_count = packet.last_fragment + 1
            ldp.push_fec(packet.fragment_index, packet.payload)
            if ldp.complete:
                decoded = ldp.decode()
                ldp.reset()
                return decoded
        else:
            print('Unsupported fragment type: {:02x}'.format(packet.fragment_type))

class LDP:
    """
    Lightweight Datagram Protocol (LDP) packet

    LDP is the L4 protocol of Outernet
    """
    __header_len = 4
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
        header = struct.unpack('>L', data[:self.__header_len])[0]
        self.type = header >> 24
        self.length = header & 0xffffff
        if self.length > len(data):
            raise ValueError('Malformed LDP packet: invalid length')

        crc = PredefinedCrc('crc-32-mpeg')
        crc.update(data[:self.length])
        if crc.crcValue != 0:
            raise ValueError('Malformed LDP packet: invalid checksum')

        self.payload = data[self.__header_len:self.length-self.__checksum_len]

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
        if packet.type not in self.__registrations:
            print('Unknown routing for packet with type {:02x}'.format(packet.type))
        else:
            self.__registrations[packet.type](packet)

    def register(self, fun, type):
        """
        Register a packet handler

        Args:
          fun: packet handler function (it must take a single argument of type LDP)
          type: type of the packets to handle
        """
        self.__registrations[type] = fun
