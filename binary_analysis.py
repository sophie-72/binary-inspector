import sys

from capstone import *
from elftools.elf.elffile import ELFFile


def process_file(filename):
    with open(filename, 'rb') as f:
        elffile = ELFFile(f)

        code = elffile.get_section_by_name('.text')
        opcodes = code.data()
        addr = code['sh_addr']

        print(f"Entry Point: {hex(elffile.header['e_entry'])}")

        md = Cs(CS_ARCH_X86, CS_MODE_64)

        instructions = []
        for i in md.disasm(opcodes, addr):
            instructions.append(i)

        for i in instructions:
            print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))

if __name__ == '__main__':
    if len(sys.argv) == 2:
        process_file(sys.argv[1])