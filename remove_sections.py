#!/usr/bin/env python

from elftools.elf.elffile import ELFFile
import base64
import sys
import traceback
import StringIO
import pprint
import struct

fn = sys.argv[1]
sn = sys.argv[2]
f = ELFFile(open(fn))
f2 = open(fn, 'r+')

shoff = f.header.e_shoff
snames = list(x.name for x in f.iter_sections())
if sn not in snames:
    sys.exit('Invalid section name.')
print(snames)
is_last = sn == snames[-1]

# remove from shstr
old_snames = '\x00'.join(snames) + '\x00'
old_i = snames.index(sn)
#if not is_last:
#    snames[old_i] = snames[-1]
#snames = snames[:-1]
new_snames = '\x00'.join(snames) + '\x00'
bytes_removed = len(old_snames) - len(new_snames)
print(bytes_removed)
new_snames += '\x00' * bytes_removed
print(new_snames)
#print(repr(new_snames))

if f.header.e_machine == 'EM_386':
    f2.seek(48)
else:
    f2.seek(60)

f2.write(struct.pack('H', len(snames)))
f2.seek(f.get_section_by_name('.shstrtab').header.sh_offset)
f2.write(new_snames)

f2.seek(f.header.e_shoff + (f.header.e_shentsize * f.header.e_shnum))
x = f2.read(f.header.e_shentsize)
f2.seek(f.header.e_shoff + (f.header.e_shentsize * old_i))
f2.write(x)

# resize .shstrtab

# if it's not the last one, overwrite the empty space
