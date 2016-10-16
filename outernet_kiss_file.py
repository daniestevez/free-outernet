#!/usr/bin/python3
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

if (len(sys.argv) != 3):
    print ('Usage: {} file.kiss output_dir'.format(sys.argv[0]))
    exit(1)

kissFile = open(sys.argv[1], 'rb')

kissDeframer = kiss.KISSDeframer()
frames = kissDeframer.push(kissFile.read())

opDefragmenter = protocols.OPDefragmenter()
router = protocols.LDPRouter()
timeservice.TimeService(router)
files.FileService(router, sys.argv[2])

for frame in frames:
    try:
        packet = opDefragmenter.push(protocols.OP(frame[14:]))
    except ValueError:
        packet = None
    if packet:
        try:
            packet = protocols.LDP(packet)
        except ValueError as e:
            packet = None
            print(e)
        if packet:
            router.route(packet)
