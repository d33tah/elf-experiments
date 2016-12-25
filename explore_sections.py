#!/usr/bin/env python

from elftools.elf.elffile import ELFFile
import base64
import sys

n = sys.argv[1]
s = open(n).read()
f = ELFFile(open(n))
b = base64.b16encode(s)

l = []
for section in f.iter_sections():
    l += [section.name.encode('utf8')]
    d = section.data()
    if not d:
        continue
    h = base64.b16encode(d)
    if b.count(h) > 1:
        print('section duplicated %d times: %s [%d]' % (b.count(h),
              section.name, len(d)))
    b = b.replace(h, '\x1b[7m' + h + '\x1b[0m')

print(l)
print(b)
