import struct
import sys

# Define ordered dictionaries for the ELF and program header formats
ELF_HEADER_FORMAT = {
    'e_ident_magic': '4s',
    'e_ident_class': 'B',
    'e_ident_data': 'B',
    'e_ident_version': 'B',
    'e_ident_osabi': 'B',
    'e_ident_abiversion': 'B',
    'e_ident_pad': '7x',
    'e_type': '<H',
    'e_machine': '<H',
    'e_version': '<I',
    'e_entry': '<Q',
    'e_phoff': '<Q',
    'e_shoff': '<Q',
    'e_flags': '<I',
    'e_ehdrsize': '<H',
    'e_phentsize': '<H',
    'e_phnum': '<H',
    'e_shentsize': '<H',
    'e_shnum': '<H',
    'e_shstrndx': '<H'
}

PHDR_FORMAT = {
    'p_type': '<I',
    'p_flags': '<I',
    'p_offset': '<Q',
    'p_vaddr': '<Q',
    'p_paddr': '<Q',
    'p_filesz': '<Q',
    'p_memsz': '<Q',
    'p_align': '<Q'
}

def unpack(fmt_dict, data):
    """Unpack data according to the format specified in fmt_dict."""
    fmt = ''.join(fmt_dict.values())
    unpacked_data = struct.unpack(fmt, data)
    return dict(zip(fmt_dict.keys(), unpacked_data))

def get_ehdr(f):
    """Extract ELF header information into a dictionary."""
    format = ''.join(ELF_HEADER_FORMAT.values())
    print(format)
    size = struct.calcsize(format)
    data = f.read(size)
    return unpack(ELF_HEADER_FORMAT, data)

def emit_hdr(d, f):
    """Write ELF header to file."""
    fmt = ''.join(ELF_HEADER_FORMAT.values())
    values = tuple(d[key] for key in ELF_HEADER_FORMAT.keys())
    f.write(struct.pack(fmt, *values))

def get_phdr(f):
    """Extract program header information into a dictionary."""
    size = struct.calcsize(''.join(PHDR_FORMAT.values()))
    data = f.read(size)
    phdr = unpack(PHDR_FORMAT, data)
    
    pos = f.tell()
    f.seek(phdr['p_offset'])
    phdr['p_data'] = f.read(phdr['p_filesz'])
    f.seek(pos)
    
    return phdr

def emit_phdr(d, f):
    """Write program header to file."""
    fmt = ''.join(PHDR_FORMAT.values())
    values = tuple(d[key] for key in PHDR_FORMAT.keys())
    f.write(struct.pack(fmt, *values))

def scrub_elf(e):
    """Modify ELF data to scrub headers."""
    e['ehdr'].update({
        'e_entry': 4194424,
        'e_shnum': 0,
        'e_shentsize': 0,
        'e_shoff': 0,
        'e_shstrndx': 0,
        'e_phnum': 1,
        'e_phoff': 64
    })

    phdr = [e['phdrs'][0]]
    text_section = e['phdrs'][1]['p_data']
    file_size = len(text_section) + 64 + 56
    phdr[0].update({
        'p_filesz': file_size,
        'p_memsz': file_size,
        'p_align': 2 * 1024 * 1024,
        'p_flags': 5
    })

    with open('scrubbed.elf', 'wb') as f:
        emit_hdr(e['ehdr'], f)
        emit_phdr(phdr[0], f)
        f.write(text_section)

# Main execution
with open(sys.argv[1], 'rb') as f:
    elf_data = {
        'ehdr': get_ehdr(f),
        'phdrs': []
    }
    f.seek(elf_data['ehdr']['e_phoff'])
    elf_data['phdrs'] = [get_phdr(f) for _ in range(elf_data['ehdr']['e_phnum'])]

scrub_elf(elf_data)
