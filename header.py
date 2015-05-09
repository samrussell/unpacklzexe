#!/usr/bin/python
# header.py by Sam Russell <sam.h.russell@gmail.com>
# Written May 2015

import struct

def parseheader(header):
  fields = struct.unpack('<HHHHHHHHHHHHHH', header)
  signature = ''.join([chr(fields[0] & 0xFF), chr(fields[0] >> 8)])
  lastblocksize = fields[1]
  numblocks = fields[2]
  relocentries = fields[3]
  headerparagraphs = fields[4]
  minextraparagraphs = fields[5]
  maxextraparagraphs = fields[6]
  ss = fields[7]
  sp = fields[8]
  checksum = fields[9]
  ip = fields[10]
  cs = fields[11]
  reloctableoffset = fields[12]
  overlaynumber = fields[13]

  print "Signature: %s" % signature
  print "Last block size: 0x%04X" % lastblocksize
  print "Number of blocks: 0x%04X" % numblocks
  print "Entries in reloc table: 0x%04X" % relocentries
  print "Number of paragraphs: 0x%04X" % headerparagraphs
  print "Memory required: 0x%04X" % minextraparagraphs
  print "Maximum memory requested: 0x%04X" % maxextraparagraphs
  print "Stack SS:SP: %04X:%04X" % (ss, sp)
  print "Checksum: 0x%04X" % checksum
  print "Initial CS:IP: %04X:%04X" % (cs, ip)
  print "Offset of reloc table: 0x%04X" % reloctableoffset
  print "Overlay number: 0x%04X" % overlaynumber


if __name__ == '__main__':
  import argparse
  parser = argparse.ArgumentParser('Provide a file to read header from')
  parser.add_argument('filename')
  args = parser.parse_args()
  filename = args.filename
  f = open(filename, 'r')
  header = f.read(0x1C)
  parseheader(header)

