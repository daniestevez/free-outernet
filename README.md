# free-outernet
Free Software Outernet receiver

**Note:** This software is now maintained by [Othernet](https://othernet.is/) as
[open-ondd](https://github.com/Othernet-Project/open-ondd). The new open-ondd has
been updated to work with the current Othernet data broadcast protocols.

This is a Free Software (Open Source) receiver for
[Outernet](http://outernet.is/) designed to work with the
[gr-outernet](https://github.com/daniestevez/gr-outernet) GNUradio Outernet
receiver modem. The key parts of the official Outernet receiver software, `ondd`
and `sdr100` are closed-source, distributed as binaries only. This project aims
to provide a Free Software alternative to `ondd`, while
[gr-outernet](https://github.com/daniestevez/gr-outernet) can be used a a
substitute for `sdr100`.

With free-outernet and gr-outernet you can receive the files that are broadcast
by Outernet file service and the time packets that are broadcast by the Outernet
time service.

All this software is the result of a reverse engineering effort, since Outernet
does not publish any documentation for the protocols they use.

You can use `free-outernet.py` to receive UDP packets in real-time from
gr-outernet or with a KISS file recorded previously by
gr-outernet. `free-outernet.py` recovers the files that are transmitted by
Outernet and prints the time packets. It also prints some interesting debug info.


Things that are not implemented/supported yet:

 * X.509 signature checking. The file announcements of the Outernet file service
   are signed with the Outernet X.509 certificate to prevent spoofing. This will
   not be implemented, as I have no interest in checking the signature. Perhaps
   some Amateur Radio operators or other people whish to use the Outernet
   protocols to exchange files, so it does not make sense for me to require
   that file announcements are signed.
 * Using the time packets to set the system time. I do not know how useful it
   is for most people. `ondd` does it, because it is designed to run standanlone
   without internet conetivity. If you have Internet connectivity it is much
   better to use NTP. If you do not have Internet connectivity and/or your need
   precise timing, it is better to use GPS. The Outernet time service only has a
   resolution of 1 second and it does not seem to account for round trip time to
   geostationary orbit (around 200ms).
 * Automatic decompression of received files. Most (perhaps all) files sent by
   the Outernet file service are `.tar.bz2` files. `ondd` extracts the files
   automatically. This is easy to implement, but it is low on my priority list,
   as it is very easy to do this manually.

## Dependencies

To install all dependencies just run: `pip3 install -r requirements.txt`

 * [crcmod](https://pypi.python.org/pypi/crcmod)
 * [zfec](https://pypi.python.org/pypi/zfec)

## Sample KISS files

You can use some [sample KISS files](https://drive.google.com/open?id=0B2pPGQkeEAfdbXFZNThCb1BLMzg) for testing.

## About LDPC decoding for files

LDPC decoding has been [implemented by George
Hopkins](https://github.com/daniestevez/free-outernet/pull/4) by reverse
engineering `ondd`.

Previously, this was not implemented, so `free-outernet` needed to receive all
the blocks for a file to be able to reconstruct it correctly. Now, it can use
the LDPC to "fill in" the missing packets in case some of them were lost.

The performance of `free-outernet` regarding FEC and LDPC decoding should
be now the same as the performance of `ondd`.
