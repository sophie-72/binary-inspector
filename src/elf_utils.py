"""Fetch data from the ELF file using the elftools library."""

import re
from typing import List, Dict

import capstone  # type: ignore
from elftools.elf.elffile import ELFFile

from src.models import Instruction


def get_file_instructions(filename) -> Dict[str, List[Instruction]]:
    """
    Extract assembly instructions from an ELF file.
    :param filename: ELF file name
    :return: dictionary of instructions for each section
    """
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

                md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

                section_instructions: List[Instruction] = []
                for i in md.disasm(opcodes, addr):
                    instruction = Instruction(i.address, i.mnemonic, i.op_str)
                    section_instructions.append(instruction)

                instructions[section.name] = section_instructions

        return instructions


def get_file_relocations(filename) -> Dict[str, str]:
    """
    Extract relocations from an ELF file.
    :param filename: ELF file name
    :return: dictionary of symbol for each relocation address
    """
    with open(filename, "rb") as f:
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


def get_file_strings(filename) -> Dict[str, str]:
    """
    Extract strings from an ELF file.
    :param filename: ELF file name
    :return: dictionary of string for each string address
    """
    rodata_strings = {}
    with open(filename, "rb") as f:
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


def get_function_symbols(filename) -> Dict[int, str]:
    """
    Extract symbols from an ELF file.
    :param filename: ELF file name
    :return: dictionary of symbols for each function address
    """
    functions = {}

    with open(filename, "rb") as f:
        elffile = ELFFile(f)

        symtab = elffile.get_section_by_name(".symtab")
        dynsym = elffile.get_section_by_name(".dynsym")
        tables = [symtab, dynsym]

        for table in tables:
            if table:
                for symbol in table.iter_symbols():
                    if symbol["st_info"]["type"] == "STT_FUNC":
                        functions[symbol["st_value"]] = symbol.name

    return functions
