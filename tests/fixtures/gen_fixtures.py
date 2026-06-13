#!/usr/bin/env python3
"""Generate minimal valid PE and ELF test fixtures for sigil integration tests."""
import struct, os

def write_minimal_pe(path):
    code = bytes([0x31, 0xC0, 0xC3, 0x00])
    data = b"SIGIL_TEST_STRING\x00"

    dos = bytearray(64)
    dos[0:2] = b'MZ'
    struct.pack_into('<I', dos, 0x3c, 64)

    pe_sig = b'PE\x00\x00'
    coff = struct.pack('<HHIIIHH', 0x8664, 2, 0x5F000000, 0, 0, 240, 0x0022)

    opt  = struct.pack('<HBB', 0x20B, 14, 0)
    opt += struct.pack('<III', len(code), len(data), 0)
    opt += struct.pack('<II',  0x1000, 0x1000)
    opt += struct.pack('<Q',   0x140000000)
    opt += struct.pack('<II',  0x1000, 0x200)
    opt += struct.pack('<HH',  6, 0)
    opt += struct.pack('<HH',  0, 0)
    opt += struct.pack('<HH',  6, 0)
    opt += struct.pack('<I',   0)
    opt += struct.pack('<II',  0x3000, 0x200)
    opt += struct.pack('<I',   0)
    opt += struct.pack('<H',   3)
    opt += struct.pack('<H',   0x140)
    opt += struct.pack('<QQ',  0x100000, 0x1000)
    opt += struct.pack('<QQ',  0x100000, 0x1000)
    opt += struct.pack('<II',  0, 16)
    opt += b'\x00' * (16 * 8)
    assert len(opt) == 240

    def section(name, vsize, vaddr, rawsize, rawptr, chars):
        n = name.encode().ljust(8, b'\x00')[:8]
        return struct.pack('<8sIIIIIIHHI', n, vsize, vaddr, rawsize, rawptr, 0, 0, 0, 0, chars)

    secs = section('.text', len(code), 0x1000, 0x200, 0x200, 0x60000020)
    secs += section('.data', len(data), 0x2000, 0x200, 0x400, 0xC0000040)

    header  = bytes(dos) + pe_sig + coff + opt + secs
    header += b'\x00' * (0x200 - len(header))
    blob = header + code.ljust(0x200, b'\x00') + data.ljust(0x200, b'\x00')

    with open(path, 'wb') as f:
        f.write(blob)
    print(f"  wrote {path} ({len(blob)} bytes)")


def write_minimal_elf(path):
    code     = bytes([0x31,0xC0, 0xB8,0x3C,0x00,0x00,0x00, 0x0F,0x05])
    EHSZ     = 64
    PHSZ     = 56
    SHSZ     = 64
    code_off = EHSZ + PHSZ
    shstr    = b'\x00.text\x00.shstrtab\x00'
    sstr_off = code_off + len(code)
    shdr_off = sstr_off + len(shstr)
    entry    = 0x400000 + code_off

    ident = b'\x7fELF' + bytes([2,1,1,0]) + b'\x00'*8  # 16 bytes
    eh = ident + struct.pack('<HHIQQQIHHHHHH',
        2, 0x3E, 1, entry, EHSZ, shdr_off, 0,
        EHSZ, PHSZ, 1, SHSZ, 3, 2)

    ph = struct.pack('<IIQQQQQQ',
        1, 5, code_off, entry, entry, len(code), len(code), 0x1000)

    def sh(name_off, typ, flags, addr, off, size, align=1):
        return struct.pack('<IIQQQQIIQQ', name_off, typ, flags, addr, off, size, 0, 0, align, 0)

    shdrs = b'\x00'*SHSZ + sh(1,1,6,entry,code_off,len(code),16) + sh(7,3,0,0,sstr_off,len(shstr))

    blob = eh + ph + code + shstr + shdrs
    with open(path, 'wb') as f:
        f.write(blob)
    print(f"  wrote {path} ({len(blob)} bytes)")


if __name__ == '__main__':
    os.makedirs('tests/fixtures', exist_ok=True)
    write_minimal_pe('tests/fixtures/minimal.exe')
    write_minimal_elf('tests/fixtures/minimal.elf')
    print("fixtures generated")
