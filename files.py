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
        self.__last_file = None

    def __description_packet(self, packet):
        """
        File description packet handler

        Registers a new file within the file dictionary

        Args:
          packet (LDP): the LDP packet to handle
        """
        cert_len = struct.unpack('>H', packet.payload[0:2])[0]
        cert = packet.payload[2:2+cert_len]
        signature_len = 128 # TODO: Deduce length from cert
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
            if f is not self.__last_file and self.__last_file and self.__last_file.maybe_reconstructable:
                self.__try_reconstruct(self.__last_file.id)
            self.__last_file = f
            f.push_block(block, block_number)
            if f.reconstructable:
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
        if f is self.__last_file:
            self.__last_file = None
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
            self.__fec_matrix = None
        self.__blocks = [None] * self.blocks
        self.__fec_blocks = list()

    def push_block(self, block, n):
        """
        Push a new block into the file

        Args:
          block (bytes): block contents
          n (int): block number
        """
        if not self.__blocks[n]:
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
        if self.__fec_blocks[n] and self.__fec_blocks[n] != block:
            print('[File service] Overwriting FEC block {} in {} with a block having different contents'.format(n, self.path))
        self.__fec_blocks[n] = block

    @property
    def maybe_reconstructable(self):
        """
        Indicates whether a reconstruction seems feasible
        """
        blocks_received = self.blocks - self.__blocks.count(None)
        if self.fec:
            blocks_received += len(self.__fec_blocks) - self.__fec_blocks.count(None)
        return blocks_received >= self.blocks

    @property
    def reconstructable(self):
        """
        Indicates whether a reconstruction is possible
        """
        return self.__blocks.count(None) == 0

    def reconstruct(self):
        """
        Try to reconstruct the file

        Returns the file contents (as bytes) if successful, None if not successful
        """
        contents = []
        if self.fec and self.fec.startswith('ldpc:'):
            if not self.__fec_matrix:
                fec_params = dict([tuple(kvp.split('=')) for kvp in self.fec[5:].split(',')])
                self.__fec_matrix = self.__fec_init_matrix(fec_params)
            blocks_remain = self.__blocks.count(None)
            fec_indices = [i for i in range(len(self.__fec_blocks)) if self.__fec_blocks[i]]
            while blocks_remain > 0:
                blocks_repaired = 0
                for fec_index in fec_indices[:]:
                    row = self.__fec_matrix[fec_index]
                    missing_indices = [i for i in row if not self.__blocks[i]]
                    if len(missing_indices) > 1:
                        continue
                    fec_indices.remove(fec_index)
                    if len(missing_indices) == 0:
                        continue
                    missing_index = missing_indices[0]
                    accum = self.__fec_blocks[fec_index]
                    for index in row:
                        if index != missing_index:
                            unpadded_size = min(self.block_size, self.size - self.block_size * index)
                            symbol = self.__blocks[index][:unpadded_size] + b'\xff' * (self.block_size - unpadded_size)
                            accum = bytes([accum[i] ^ symbol[i] for i in range(len(accum))])
                    missing_unpadded_size = min(self.block_size, self.size - self.block_size * missing_index)
                    self.__blocks[missing_index] = accum[:missing_unpadded_size]
                    blocks_repaired += 1
                    blocks_remain -= 1
                if blocks_repaired == 0:
                    print('Unable to reconstruct file {}'.format(self.path))
                    return
            contents = bytes().join(self.__blocks)
        else: # No (supported) FEC
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

        return contents

    def __fec_init_matrix(self, params):
        """
        Build a matrix for FEC

        Args:
          params (dict): Parameters used to encode the data
        """
        k = int(params['k'])
        n = int(params['n'])
        n1 = int(params['N1'])
        seed = int(params['seed']) if 'seed' in params else 1
        prng = self.__fec_prng(seed)
        p_tbl = [ p % (n - k) for p in range(k * n1)]
        matrix = [[] for _ in range(n - k)]
        t = 0
        for col in range(k):
            for h in range(n1):
                i = t
                while i < k * n1 and col in matrix[p_tbl[i]]:
                    i += 1
                if i >= k * n1:
                    while True:
                        row = next(prng) % (n - k)
                        if col not in matrix[row]:
                            break
                    matrix[row].append(col)
                else:
                    while True:
                        p = next(prng) % (k * n1 - t) + t
                        if col not in matrix[p_tbl[p]]:
                            break
                    matrix[p_tbl[p]].append(col)
                    p_tbl[p] = p_tbl[t]
                    t += 1
        for row in range(n - k):
            degree = len(matrix[row])
            if degree == 0:
                col = next(prng) % k
                matrix[row].append(col)
            if degree <= 1:
                while True:
                    col = next(prng) % k
                    if col not in matrix[row]:
                        break
                matrix[row].append(col)
        return matrix

    def __fec_prng(self, seed):
        """
        Generate pseudo random numbers

        Implementation of the Park-Miller random number generator

        Args:
          seed (int): Seed
        """
        value = seed
        while True:
            value = (7**5 * value) % (2**31 - 1)
            yield value
