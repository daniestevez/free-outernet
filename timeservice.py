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

"""Outernet time service receiver

Receives time packets in the Outernet service
"""

__author__ = 'Daniel Estevez'
__copyright__ = 'Copyright 2016, Daniel Estevez'
__license__ = 'GPLv3'
__maintainer__ = 'Daniel Estevez'
__email__ = 'daniel@destevez.net'


import datetime
import struct

class TimeService:
    """
    Packet handler for Outernet time service

    Gets time packets from LDPRouter() and prints them
    """
    def __init__(self, router):
        """
        Initialize time service handler

        Args:
          router (LDPRouter): LDP router to get packets from
        """
        router.register(self.__get, 0x81)

    def __get(self, packet):
        """
        Time packet handler

        Prints the timestamp in the packet

        Args:
          packet (LDP): the LDP time packet
        """
        payload = packet.payload
        while len(payload) > 2:
            desc_id, desc_len = struct.unpack('>BB', payload[0:2])
            if desc_len > len(payload) - 2:
                break
            data = payload[2:desc_len+2]
            payload = payload[desc_len+2:]
            if desc_id == 0x01:
                server_id = str(data, 'utf-8')
                print('[Time service] Server ID: {}'.format(server_id))
            elif desc_id == 0x02 and len(data) == 8:
                timestamp = datetime.datetime.utcfromtimestamp(struct.unpack('>Q', data)[0])
                print('[Time service] Server time: {} UTC'.format(timestamp))
            else:
                print('[Time service] Unknown descriptor {:02x}'.format(desc_id))
