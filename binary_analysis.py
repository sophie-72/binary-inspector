import re
import sys
from typing import List

from capstone import *
from elftools.elf.elffile import ELFFile

from models import Instruction
from translation import translate_instructions


def get_file_instructions(filename):
    with open(filename, "rb") as f:
        elffile = ELFFile(f)

        instructions = {}
        for section in elffile.iter_sections():
            if section["sh_type"] in (
                "SHT_PROGBITS",
                "SHT_NOBITS",
            ):
                opcodes = section.data()
                addr = section["sh_addr"]

                md = Cs(CS_ARCH_X86, CS_MODE_64)

                section_instructions: List[Instruction] = []
                for i in md.disasm(opcodes, addr):
                    instruction = Instruction(i.address, i.mnemonic, i.op_str)
                    section_instructions.append(instruction)

                instructions[section.name] = section_instructions

        return instructions


def write_to_file(executable_name, instructions):
    filename = f"{executable_name}.asm"

    with open(filename, "w") as file:
        for name, instructions in instructions.items():
            file.write(f"; {name}\n")

            for instruction in instructions:
                file.write(
                    f"0x{instruction.address:x}:\t{instruction.mnemonic}\t{instruction.op_str}\t; {instruction.translation}\n"
                )

            file.write(f"\n")


def get_file_relocations():
    with open(executable, "rb") as f:
        elffile = ELFFile(f)
        reladyn = elffile.get_section_by_name(".rela.dyn")

        symbol_table = elffile.get_section(reladyn["sh_link"])

        relocations = {}
        for relocation in reladyn.iter_relocations():
            symbol = symbol_table.get_symbol(relocation["r_info_sym"])

            if symbol:
                addr = hex(relocation["r_offset"])
                relocations[addr] = symbol.name

        return relocations


def get_file_strings():
    rodata_strings = {}
    with open(executable, "rb") as f:
        elffile = ELFFile(f)

        rodata_section = elffile.get_section_by_name(".rodata")
        if rodata_section:
            rodata_data = rodata_section.data()
            rodata_address = rodata_section["sh_addr"]

            # Extract strings from the .rodata section
            strings = re.findall(
                rb"[\x20-\x7E]+", rodata_data
            )  # ASCII printable characters
            for s in strings:
                start_index = rodata_data.index(s)
                string_address = rodata_address + start_index
                rodata_strings[hex(string_address)] = s.decode("utf-8")

        return rodata_strings


def main():
    instructions = get_file_instructions(executable)
    relocations = get_file_relocations()
    strings = get_file_strings()
    translate_instructions(instructions, relocations, strings)
    write_to_file(
        executable,
        instructions,
    )


if __name__ == "__main__":
    if len(sys.argv) == 2:
        executable = sys.argv[1]
        main()
