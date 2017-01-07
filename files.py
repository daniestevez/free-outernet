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

"""Outernet file service receiver

Receives files in the Outernet service and saves them to disk
"""

__author__ = 'Daniel Estevez'
__copyright__ = 'Copyright 2016, Daniel Estevez'
__license__ = 'GPLv3'
__maintainer__ = 'Daniel Estevez'
__email__ = 'daniel@destevez.net'


import struct
import xml.etree.ElementTree as ET
import math
import hashlib
import os.path
import os

import binascii

class FileService:
    """
    Packet handler for Outernet file service

    Gets packets from LDPRouter() and handles file reconstruction
    using the File() class
    """
    __block_header_len = 6
    
    def __init__(self, router, files_path):
        """
        Initialize file service handler

        Args:
          router (LDPRouter): LDP router to get packets from
          files_path (str): path to save files to
        """
        router.register(self.__description_packet, 0x69)
        router.register(self.__block_packet, 0x18)
        router.register(self.__fec_packet, 0xff)
        router.register(self.__signaling_packet, 0x42)
        router.register(self.__signaling_packet, 0x5a)

        self.__files = dict()
        self.__files_path = files_path

    def __description_packet(self, packet):
        """
        File description packet handler

        Registers a new file within the file dictionary

        Args:
          packet (LDP): the LDP packet to handle
        """
        cert_len = struct.unpack('>H', packet.payload[0:2])[0]
        cert = packet.payload[2:2+cert_len]
        signature_len = 256 # TODO: Deduce length from cert
        signature = packet.payload[2+cert_len:2+cert_len+signature_len]
        xml = packet.payload[2+cert_len+signature_len:]
        # TODO: Verify hash matches the signature (RSA with SHA256)
        f = File(xml)
        self.__files[f.id] = f
        print('[File service] New file announced: {} size {} bytes'.format(f.path, f.size))

    def __block_packet(self, packet):
        """
        File block packet handler

        Pushes the block to the corresponding file and
        initiates file recovery if this is the last packet

        Args:
          packet (LDP): the LDP packet to handle
        """
        file_id, block_number = struct.unpack('>IH', packet.payload[:self.__block_header_len])
        block = packet.payload[self.__block_header_len:]
        if file_id in self.__files:
            f = self.__files[file_id]
            f.push_block(block, block_number)
            if block_number + 1 == f.blocks:
                self.__try_reconstruct(file_id)

    def __fec_packet(self, packet):
        """
        File FEC packet handler

        Pushes the FEC block to the corresponding file

        Args:
          packet (LDP): the LDP packet to handle
        """
        file_id, block_number = struct.unpack('>IH', packet.payload[:self.__block_header_len])
        block = packet.payload[self.__block_header_len:]
        if file_id in self.__files:
            f = self.__files[file_id]
            f.push_fec(block, block_number)

    def __signaling_packet(self, packet):
        """
        File signaling packet handler

        Args:
          packet (LDP): the LDP packet to handle
        """
        print('[File service] Received signaling information (not implemented yet)')
        # TODO Update file dictionary based on signed, deflated XML

    def __try_reconstruct(self, file_id):
        """
        Try to reconstruct file and save to disk

        Args:
          file_id (int): the file to reconstruct
        """
        f = self.__files[file_id]
        contents = f.reconstruct()
        if not contents:
            return

        path = os.path.join(self.__files_path, f.path)
        os.makedirs(os.path.dirname(path), exist_ok = True)
        out = open(os.path.join(self.__files_path, f.path), 'wb')
        out.write(contents)
        out.close()
        del self.__files[file_id]
        print('[File service] File reconstructed: {}'.format(f.path))
        

class File:
    """
    File object for file reconstruction
    """
    def __init__(self, xml):
        """
        Create new file

        Args:
          xml (str): XML description of the file
        """
        root = ET.fromstring(xml)
        self.id = int(root.find('id').text)
        self.path = root.find('path').text
        self.hash = root.find('hash').text
        self.size = int(root.find('size').text)
        self.block_size = int(root.find('block_size').text)
        self.blocks = math.ceil(self.size / self.block_size)
        self.fec = root.find('fec')
        if self.fec != None:
            self.fec = self.fec.text
        self.__blocks = [None] * self.blocks
        self.__fec_blocks = list()

    def push_block(self, block, n):
        """
        Push a new block into the file

        Args:
          block (bytes): block contents
          n (int): block number
        """
        if self.__blocks[n]:
            raise ValueError('File.push_block(): block already received!')
        self.__blocks[n] = block

    def push_fec(self, block, n):
        """
        Push a new FEC block into the file

        Args:
          block (bytes): block contents
          n (int): block number
        """
        if (len(self.__fec_blocks) <= n):
            self.__fec_blocks.extend([None]*(n - len(self.__fec_blocks) + 1))
        if self.__fec_blocks[n]:
            raise ValueError('File.push_fec(): FEC block already received!')
        self.__fec_blocks[n] = block
    
    def reconstruct(self):
        """
        Try to reconstruct the file

        Returns the file contents (as bytes) if successful, None if not successful
        """

        # TODO implement FEC for file reconstruction
        if self.fec:
            print('--------------------------------------------------------------------')
            print('FEC debug info for file {} (FEC decoding not implemented yet)'.format(self.path))
            print(self.fec)
            if None in self.__fec_blocks:
                print('Some FEC blocks are missing')
            else:
                fec = bytes().join(self.__fec_blocks)
                print('Length of FEC data: {} bytes; File size: {} bytes'.format(len(fec), self.size))
            print('--------------------------------------------------------------------')
        
        if None in self.__blocks:
            print('Some blocks are missing. Cannot reconstruct file {}'.format(self.path))
            return

        contents = bytes().join(self.__blocks)
        if len(contents) != self.size:
            print('File length mismatch. Cannot reconstruct file {}'.format(self.path))
            return

        h = hashlib.sha256()
        h.update(contents)
        if h.hexdigest() != self.hash:
            print('File sha256sum mismatch. Cannot reconstruct file {}'.format(self.path))
            return

        return bytes().join(self.__blocks)
