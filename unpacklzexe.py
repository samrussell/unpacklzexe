#!/usr/bin/python
# unpacklzexe.py by Sam Russell <sam.h.russell@gmail.com>
# Written May 2015

import struct
import json

def parseheader(header):
  fields = struct.unpack('<HHHHHHHHHHHHHH', header)
  headerdata = {}
  headerdata['signature'] = ''.join([chr(fields[0] & 0xFF), chr(fields[0] >> 8)])
  headerdata['partpage'] = fields[1]
  headerdata['pagecnt'] = fields[2]
  headerdata['relocnt'] = fields[3]
  headerdata['hdrsize'] = fields[4]
  headerdata['minalloc'] = fields[5]
  headerdata['maxalloc'] = fields[6]
  headerdata['initss'] = fields[7]
  headerdata['initsp'] = fields[8]
  headerdata['chksum'] = fields[9]
  headerdata['initip'] = fields[10]
  headerdata['initcs'] = fields[11]
  headerdata['tabloff'] = fields[12]
  headerdata['overlayno'] = fields[13]

  return headerdata

def generateheader(headerdata):
  headerbase = struct.pack('<BBHHHHHHHHHHHHH',
                            ord(headerdata['signature'][0]),
                            ord(headerdata['signature'][1]),
                            headerdata['partpage'],
                            headerdata['pagecnt'],
                            headerdata['relocnt'],
                            headerdata['hdrsize'],
                            headerdata['minalloc'],
                            headerdata['maxalloc'],
                            headerdata['initss'],
                            headerdata['initsp'],
                            headerdata['chksum'],
                            headerdata['initip'],
                            headerdata['initcs'],
                            headerdata['tabloff'],
                            headerdata['overlayno'])
  return headerbase

def checksignaturelz91(checkstring):
  if checkstring == "LZ91":
    return True
  return False

def unpacklz91data(indata):
  outdata = ""
  si = 0
  dx = 0x10
  bp = struct.unpack('<H', indata[si:si+2])[0]
  si = si + 2
  bit = 0
  while True:
    bit = bp & 1
    bp = bp >> 1
    dx = dx - 1
    if dx == 0:
      bp = struct.unpack('<H', indata[si:si+2])[0]
      si = si + 2
      dx = 0x10
    if bit == 1:
      outdata = outdata + indata[si]
      si = si + 1
      continue
    cx = 0
    bit = bp & 1
    bp = bp >> 1
    dx = dx - 1
    if dx == 0:
      bp = struct.unpack('<H', indata[si:si+2])[0]
      si = si + 2
      dx = 0x10
    if bit == 0:
      bit = bp & 1
      bp = bp >> 1
      dx = dx - 1
      if dx == 0:
        bp = struct.unpack('<H', indata[si:si+2])[0]
        si = si + 2
        dx = 0x10
      cx = ((cx << 1) + bit) & 0xFFFF
      bit = bp & 1
      bp = bp >> 1
      dx = dx - 1
      if dx == 0:
        bp = struct.unpack('<H', indata[si:si+2])[0]
        si = si + 2
        dx = 0x10
      cx = ((cx << 1) + bit) & 0xFFFF
      cx = cx + 2
      tempbyte = struct.unpack('<B', indata[si:si+1])[0]
      si = si + 1
      bx = tempbyte - 0x100
      for i in range(cx):
        tempbyte = outdata[bx]
        outdata = outdata + tempbyte
      continue
    ax = struct.unpack('<H', indata[si:si+2])[0]
    si = si + 2
    bx = ax
    bh = bx >> 8
    bh = bh >> 3
    bx = (bh << 8) + (bx & 0xff)
    bx = bx - 0x2000
    ah = ax >> 8
    ah = ah & 0x7
    if ah != 0:
      cx = ah + 2
      for i in range(cx):
        tempbyte = outdata[bx]
        outdata = outdata + tempbyte
      continue
    al = struct.unpack('<B', indata[si:si+1])[0]
    si = si + 1
    if al == 0:
      break
    if al != 1:
      cx = al + 1
      for i in range(cx):
        tempbyte = outdata[bx]
        outdata = outdata + tempbyte
      continue
    # byte 0x01 is a signal to rephrase the current mem pointer
    # this makes sense under DOS, but is unnecessary here with no 16-bit segments
    #if al != 1:
    #  print "si: %04X di:%04X al should be 1 but is %02X" % (si, len(outdata), al)
    #print "pretending to realign segments"
  return outdata

def unpacklz91reloc(relocdata):
  relocoutstr = bytearray()
  si = 0
  dx = 0
  di = 0
  while True:
    al = struct.unpack("<B", relocdata[si:si+1])[0]
    si = si + 1
    if al == 0:
      ax = struct.unpack("<H", relocdata[si:si+2])[0]
      si = si + 2
      if ax == 0:
        dx = dx + 0xfff
        dx = dx % 0x10000
        es = dx
        continue
      if ax == 1:
        break
    else:
      ax = al
    di = di + ax
    ax = di
    di = di & 0xf
    ax = ax >>4
    dx = dx + ax
    es = dx
    relocoutstr = relocoutstr + struct.pack('<HH', di, es)
  return relocoutstr

def unpacklz91(data, outfile):
  header = data[:0x1C]
  headerdata = parseheader(header)
  # size of header is hdrsize x 0x10
  headersize = headerdata['hdrsize'] * 0x10
  # loader stub is at CS:0000 + hdrsize
  loadercs = headerdata['initcs']
  loaderoffset = loadercs * 0x10 + headersize
  #print "Loader data is at %02X" % loaderoffset
  # ss is at 0x06 from start
  # sp is at 0x04 from start
  # cs is at 0x02 from start
  # ip is at 0x00 from start
  exeip = struct.unpack('<H', data[loaderoffset + 0x00:loaderoffset + 0x02])[0]
  execs = struct.unpack('<H', data[loaderoffset + 0x02:loaderoffset + 0x04])[0]
  exesp = struct.unpack('<H', data[loaderoffset + 0x04:loaderoffset + 0x06])[0]
  exess = struct.unpack('<H', data[loaderoffset + 0x06:loaderoffset + 0x08])[0]
  #print "EXE loads at %04X:%04X with SS:SP %04X:%04X" % (execs, exeip, exess, exesp)
  # now just to unpack :)
  # packed data is data[0x20:loaderoffset]
  # packed reloc is data[loaderoffset+0x158]
  packeddata = data[0x20:loaderoffset]
  packedreloc = data[loaderoffset+0x158:]
  unpackeddata = unpacklz91data(packeddata)
  unpackedreloc = unpacklz91reloc(packedreloc)
  # now just to generate new header and build exe
  # deal with partpage and pagecnt after we do relocs
  # number of relocs = len(unpackedreloc)/4
  headerdata['relocnt'] = len(unpackedreloc)/4
  # header is now 0x1C + relocnt*4 and round up to nearest 0x10
  headersize = headerdata['relocnt']*4 + 0x1C
  extra = headersize % 0x10
  if extra > 0:
    headersize = headersize + 0x10 - extra
  # remember we need padding on end of header
  padding = ''.join(['\x00' for x in range(0x10 - extra)])
  headerdata['hdrsize'] = headersize/0x10
  # can now calculate total file size
  filesize = headersize + len(unpackeddata)
  headerdata['partpage'] = filesize % 0x200
  headerdata['pagecnt'] = filesize / 0x200
  if headerdata['partpage'] > 0:
    headerdata['pagecnt'] = headerdata['pagecnt'] + 1
  lessmemory = len(unpackeddata) - len(packeddata)
  headerdata['minalloc'] = headerdata['minalloc'] - lessmemory/0x10
  headerdata['maxalloc'] = 0xffff
  headerdata['chksum'] = 0
  # file data for loading
  headerdata['initss'] = exess
  headerdata['initsp'] = exesp
  headerdata['initip'] = exeip
  headerdata['initcs'] = execs
  headerdata['tabloff'] = 0x1c
  headerdata['overlayno'] = 0
  # we are now good to go
  newheader = generateheader(headerdata)
  # now write newheader + unpackedreloc + padding + unpackeddata
  fout = open(outfile, 'w')
  fout.write(newheader + unpackedreloc + padding + unpackeddata)
  return 1

def unpacklzexe(data, outfile):
  if checksignaturelz91(data[0x1c:0x20]):
    print "Detected LZ91 file"
    return unpacklz91(data, outfile)
  return None


if __name__ == '__main__':
  # run test suite
  import argparse
  parser = argparse.ArgumentParser('Provide an LZEXE packed file')
  parser.add_argument('infile')
  parser.add_argument('outfile')
  args = parser.parse_args()
  filename = args.infile
  f = open(filename, 'r')
  data = f.read()
  unpacked = unpacklzexe(data, args.outfile)
  if unpacked:
    print "Done"
  else:
    print "Not a valid LZ91 file, could not unpack"


