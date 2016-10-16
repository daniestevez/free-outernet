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

"""KISS framing library"""

__author__ = 'Daniel Estevez'
__copyright__ = 'Copyright 2016, Daniel Estevez'
__license__ = 'GPLv3'
__maintainer__ = 'Daniel Estevez'
__email__ = 'daniel@destevez.net'

import collections

class KISSDeframer():
    """
    Deframe a stream of bytes into KISS frames
    """
    __FEND = 0xc0
    __FESC = 0xdb
    __TFEND = 0xdc
    __TFESC = 0xdd
    
    def __init__(self):
        """
        Initialize KISS deframer
        """
        self.__kiss = collections.deque()
        self.__pdu = bytearray()
        self.__transpose = False

    def push(self, data):
        """
        Push a chunk of data bytes into the deframer

        Returns a list of the frames that have being
        successfully deframed (in the same order as in the stream)

        Args:
          data (bytes): the chunk of bytes to push
        """
        pdus = list()
        
        self.__kiss.extend(data)
        
        while self.__kiss:
            c = self.__kiss.popleft()
            if c == self.__FEND:
                if self.__pdu and not self.__pdu[0] & 0x0f:
                    pdus.append(bytes(self.__pdu[1:]))
                self.__pdu = bytearray()
            elif self.__transpose:
                if c == self.__TFEND:
                    self.__pdu.append(self.__FEND)
                elif c == self.__TFESC:
                    self.__pdu.append(self.__FESC)
                self.__transpose = False
            elif c == self.__FESC:
                self.__transpose = True
            else:
                self.__pdu.append(c)

        return pdus
