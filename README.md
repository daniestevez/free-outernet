# free-outernet
Free Software Outernet receiver

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

 * LDPC decoding (see below)
 * X.509 signature checking. The file announcements of the Outernet file service
   are signed with the Outernet X.509 certificate to prevent spoofing. This will
   not be implemented, as I have no interest in checking the signature. Perhaps
   some Amateur Radio operators or other people whish to use the Outernet
   protocols to exchange files, so it does not make sense for me to require
   that file announcements are signed.
 * Some weird Outernet frames which I do not know what they do. They do not seem
   to do something very important, though.
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

## What is this LDPC decoding thing?

LDPC is the only important thing that `ondd` does and that is not implemented in
free-outernet. It is a Forward Error Correction code designed to permit to
recover a complete file even if you have some missing blocks which could not be
received. Without LDPC decoding, you need to receive all the blocks of the file
or you cannot recover the file.

If you have a good uninterrupted signal, there is no reason why you should fail
to receive some of the blocks, so you will have all the file blocks when the
file transmission ends and LDPC decoding is not necessary. This has being tested
with real world recordings.

However, if your signal is not very good or objects get in the way of your
receiver ocassionally, you will have a few blocks missing. `ondd` is able to use
LDPC decoding to recover the whole file, while free-outernet is unable to do so.

Of course, LDPC or some other Forward Error Correction is a very good idea to
have on a file broadcast service such as this. What I mean is that it is
possible to have a fully functional receiver without LDPC decoding, and this is
what free-outernet does.

The problem with LDPC codes is that there are many different LDPC codes (and
Outernet uses several different codes depending on file size and so on). Also,
implementing an LDPC decoder is not trivial. Unless I manage to find an
open-source library that implements the LDPC codes used on Outernet or I get
some help from somebody with more experience with LDPC codes, implementing LDPC
decoding in free-outernet is low on my priority list.

For now, free-outernet prints some debug information about the LDPC codes to
help anyone interested in this get started in trying to reverse engineer the
LDPC codes used in Outernet.
