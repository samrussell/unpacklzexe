# unpacklzexe
Python unpacker for LZ91 packed EXE files

## Current features
- Unpacks LZ91 EXEs
- Doesn't unpack LZ90
- Tested on the commander keen series

## Usage
./unpacklzexe.py input.exe output.exe

## Previewing DOS headers
./header input.exe

### Output:
> Signature: MZ
> Last block size: 0x01D3
> Number of blocks: 0x00C8
> Entries in reloc table: 0x0000
> Number of paragraphs: 0x0002
> Memory required: 0x24EC
> Maximum memory requested: 0xFFFF
> Stack SS:SP: 3D09:0080
> Checksum: 0x0000
> Initial CS:IP: 1826:000E
> Offset of reloc table: 0x001C
> Overlay number: 0x0000

# Why do this?
My reversing skills are a bit rusty, so I tried reversing one of my old favorite games. The first step involved unpacking the EXE before I could disassemble it, so I figured reversing the unpacking code would be useful

I hope a python version of UNLZEXE will be useful for others. The code for the actual decompression is a bit gnarly (built directly from the disassembly!), but the rest of it should hopefully make sense and be helpful.

