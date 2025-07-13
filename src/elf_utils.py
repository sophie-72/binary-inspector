"""Fetch data from the ELF file using the elftools library."""

import re
from typing import Dict

import capstone  # type: ignore
from elftools.elf.elffile import ELFFile

from src.models import Instruction
from src.types import SectionNameToInstructionsMapping, AddressToStringMapping


class ELFProcessor:
    """Extract information from an ELF file."""

    def __init__(self, elffile: ELFFile):
        self.elffile = elffile

    def get_file_instructions(self) -> SectionNameToInstructionsMapping:
        """
        Extract assembly instructions from an ELF file.
        :return: A dictionary mapping section names to lists of instructions.
        """

        instructions = {}
        for section in self.elffile.iter_sections():
            if section["sh_type"] in (
                "SHT_PROGBITS",
                "SHT_NOBITS",
            ):
                opcodes = section.data()
                addr = section["sh_addr"]

                md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

                section_instructions = []
                for i in md.disasm(opcodes, addr):
                    instruction = Instruction(i.address, i.mnemonic, i.op_str)
                    section_instructions.append(instruction)

                instructions[section.name] = section_instructions

        return instructions

    def get_file_relocations(self) -> AddressToStringMapping:
        """
        Extract relocations from an ELF file.
        :return: A dictionary mapping relocation addresses to symbols.
        """
        reladyn = self.elffile.get_section_by_name(".rela.dyn")

        symbol_table = self.elffile.get_section(reladyn["sh_link"])

        relocations = {}
        for relocation in reladyn.iter_relocations():
            symbol = symbol_table.get_symbol(relocation["r_info_sym"])

            if symbol:
                addr = hex(relocation["r_offset"])
                relocations[addr] = symbol.name

        return relocations

    def get_file_strings(self) -> AddressToStringMapping:
        """
        Extract strings from an ELF file.
        :return: A dictionary mapping string addresses to strings.
        """
        rodata_strings = {}

        rodata_section = self.elffile.get_section_by_name(".rodata")
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

    def get_function_names(self) -> Dict[int, str]:
        """
        Extract function names from an ELF file.
        :return: A dictionary mapping function addresses to function names.
        """
        functions = {}

        symtab = self.elffile.get_section_by_name(".symtab")
        dynsym = self.elffile.get_section_by_name(".dynsym")
        tables = [symtab, dynsym]

        for table in tables:
            if table:
                for symbol in table.iter_symbols():
                    if symbol["st_info"]["type"] == "STT_FUNC":
                        functions[symbol["st_value"]] = symbol.name

        return functions
