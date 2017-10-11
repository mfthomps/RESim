#!/usr/bin/python

import os
import struct
import sys

def main():
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: %s filename\n" % sys.argv[0]);
        return 1
    r = valid_cgc_executable_file(sys.argv[1])
    if not r:
        return 1

    filp = open(sys.argv[1], "r")
    print_program_hdrs(filp)
    filp.close()

    return 0

def print_program_hdrs(filp):
    header_size = 16 + 2*2 + 4*5 + 2*6
    buf = read_bytes(filp, 0, header_size)
    (cgcef_type, cgcef_machine, cgcef_version, cgcef_entry, cgcef_phoff,
     cgcef_shoff, cgcef_flags, cgcef_ehsize, cgcef_phentsize, cgcef_phnum,
     cgcef_shentsize, cgcef_shnum, cgcef_shstrndx) =                        \
     struct.unpack("<xxxxxxxxxxxxxxxxHHLLLLLHHHHHH", buf)

    phent_size = 8 * 4

    if cgcef_phnum == 0:
        warnx("No program headers")
        return
    if cgcef_phentsize != phent_size:
        warnx("Invalid program header size")
        return

    PT_NULL = 0
    PT_LOAD = 1
    PT_PHDR = 6
    PT_GNU_STACK = 0x60000000 + 0x474e551
    PT_CGCPOV2 = 0x6ccccccc

    PF_X = (1 << 0)
    PF_W = (1 << 1)
    PF_R = (1 << 2)

    for i in xrange(0, cgcef_phnum):
        hdr = read_bytes(filp, cgcef_phoff + phent_size * i, phent_size)
        (p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags,
         p_align) = struct.unpack("<IIIIIIII", hdr)
        if p_type == PT_NULL:
            print "Section[%u]: NULL" % (i)
        else:
            if p_type == PT_LOAD:
                print "Section[%u]: LOAD" % (i)
            elif p_type == PT_PHDR:
                print "Section[%u]: Program Header" % (i)
            elif p_type == PT_CGCPOV2:
                print "Section[%u]: CGC PoV2 memory" % (i)
            elif p_type == PT_GNU_STACK:
                print "Section[%u]: Deprecated STACK" % (i)
            else:
                print "Section[%u]: INVALID(%xh)" % (i, p_type)
            perms = ""
            if p_flags & PF_R:
                perms = perms + "R"
            if p_flags & PF_W:
                perms = perms + "W"
            if p_flags & PF_X:
                perms = perms + "X"
            print "\tPermissions: %s" % (perms)
            print "\tMemory: 0x%x + 0x%x" % (p_vaddr, p_memsz)
            print "\tFile: 0x%x + 0x%x" % (p_offset, p_filesz)


    return 0


def valid_cgc_executable_file(filename):
    filp = open(filename, "r")

    r = verify_ident(filp)
    if not r and verify_header(filp):
        r = -1
    if not r and verify_section_hdrs(filp):
        r = -1
    if not r and verify_program_hdrs(filp):
        r = -1

    filp.close()
    if r:
        print("ERROR: not a DECREE executable")
        return False
    return True

def verify_ident(filp):
    CGCEFMAG0 = 0x7f
    CGCEFMAG1 = 'C'
    CGCEFMAG2 = 'G'
    CGCEFMAG3 = 'C'
    CGCEFCLASS32 = 1
    CGCEFDATA2LSB = 1
    CGCEFVERSION = 1
    CGCEFOSABI_CGCOS = 0x43
    CGCEFABIVERSION = 1

    r = 0

    buf = read_bytes(filp, 0, 9)
    (cgcef_mag0, cgcef_mag1, cgcef_mag2, cgcef_mag3, cgcef_class, cgcef_data,
     cgcef_version, cgcef_osabi, cgcef_abiversion) =                        \
     struct.unpack("<bcccbbbbb", buf)

    if cgcef_mag0 != CGCEFMAG0 or cgcef_mag1 != CGCEFMAG1 or                \
       cgcef_mag2 != CGCEFMAG2 or cgcef_mag3 != CGCEFMAG3:
        warnx("did not identify as a DECREE binary (ident %s%s%s)" %
              (cgcef_mag1, cgcef_mag2, cgcef_mag3))
        return -1
    if cgcef_class != CGCEFCLASS32:
        warnx("did not identify as a 32bit binary")
        r = -1
    if cgcef_data != CGCEFDATA2LSB:
        warnx("did not identify as a little endian binary")
        r = -1
    if cgcef_version != CGCEFVERSION:
        warnx("unknown CGCEF version")
        r = -1
    if cgcef_osabi != CGCEFOSABI_CGCOS:
        warnx("did not identify as a DECREE ABI binary")
        r = -1
    if cgcef_abiversion != CGCEFABIVERSION:
        warnx("did not identify as a v1 DECREE ABI binary")
        r = -1
    return r

def verify_header(filp):
    header_size = 16 + 2*2 + 4*5 + 2*6
    buf = read_bytes(filp, 0, header_size)
    (cgcef_type, cgcef_machine, cgcef_version, cgcef_entry, cgcef_phoff,
     cgcef_shoff, cgcef_flags, cgcef_ehsize, cgcef_phentsize, cgcef_phnum,
     cgcef_shentsize, cgcef_shnum, cgcef_shstrndx) =                        \
     struct.unpack("<xxxxxxxxxxxxxxxxHHLLLLLHHHHHH", buf)

    ET_EXEC = 2
    EM_386 = 3
    EV_CURRENT = 1
    r = 0
    if cgcef_ehsize != header_size:
        warnx("invalid header size")
        r = -1
    if cgcef_type != ET_EXEC:
        warnx("did not identify as an executable")
        r = -1
    if cgcef_machine != EM_386:
        warnx("did not identify as i386")
        r = -1
    if cgcef_version != EV_CURRENT:
        warnx("did not identify as a version 1 binary")
        r = -1
    if cgcef_flags != 0:
        warnx("contained unsupported flags")
        r = -1
    return r 

def verify_section_hdrs(filp):
    header_size = 16 + 2*2 + 4*5 + 2*6
    buf = read_bytes(filp, 0, header_size)
    (cgcef_type, cgcef_machine, cgcef_version, cgcef_entry, cgcef_phoff,
     cgcef_shoff, cgcef_flags, cgcef_ehsize, cgcef_phentsize, cgcef_phnum,
     cgcef_shentsize, cgcef_shnum, cgcef_shstrndx) =                        \
     struct.unpack("<xxxxxxxxxxxxxxxxHHIIIIIHHHHHH", buf)

    if cgcef_shnum != 0:
        # not a fatal error
        #warnx("WARNING: DECREE Executable contained optional section headers")
        pass
    return 0;

def verify_program_hdrs(filp):
    header_size = 16 + 2*2 + 4*5 + 2*6
    buf = read_bytes(filp, 0, header_size)
    (cgcef_type, cgcef_machine, cgcef_version, cgcef_entry, cgcef_phoff,
     cgcef_shoff, cgcef_flags, cgcef_ehsize, cgcef_phentsize, cgcef_phnum,
     cgcef_shentsize, cgcef_shnum, cgcef_shstrndx) =                        \
     struct.unpack("<xxxxxxxxxxxxxxxxHHLLLLLHHHHHH", buf)

    phent_size = 8 * 4

    r = 0
    if cgcef_phnum == 0:
        warnx("No program headers")
        r = -1
    if cgcef_phentsize != phent_size:
        warnx("Invalid program header size")
        r = -1
    if cgcef_phnum > 128:
        warnx("Too many program headers")
        # Don't go off into the weeds checking them
        return -1

    PT_NULL = 0
    PT_LOAD = 1
    PT_PHDR = 6
    PT_GNU_STACK = 0x60000000 + 0x474e551
    PT_CGCPOV2 = 0x6ccccccc
    for i in xrange(0, cgcef_phnum):
        hdr = read_bytes(filp, cgcef_phoff + phent_size * i, phent_size)
        (p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags,
         p_align) = struct.unpack("<IIIIIIII", hdr)
        if p_type == PT_NULL or     \
           p_type == PT_LOAD or     \
           p_type == PT_PHDR or     \
           p_type == PT_CGCPOV2:
            pass
        elif p_type == PT_GNU_STACK:
            #warnx("PT_GNU_STACK program header was detected. These will be considered invalid prior to CQE.");
            pass
        else:
            #warnx("Invalid program header #%d %xh. These will be considered invalid prior to CQE" % (i, p_type))
#            r = -1
            pass


    return r


def read_bytes(filp, offset, size):
    filp.seek(offset, 0);    # absolute offset seek
    buf = filp.read(size)
    if len(buf) != size:
        raise Exception("Short read")
    return buf

def warnx(str):
    sys.stderr.write(os.path.basename(sys.argv[0]) + ":" + " " + str + "\n")
    

if __name__ == '__main__':
    sys.exit(main())
