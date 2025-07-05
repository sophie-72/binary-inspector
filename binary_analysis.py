import re
import sys
from typing import List, Dict, Optional

from capstone import *
from elftools.elf.elffile import ELFFile

from models import Instruction, Function
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


def write_to_file(
    executable_name: str, instructions: Dict[str, List[Instruction]]
) -> None:
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


def get_function_symbols() -> Dict[int, str]:
    functions = {}

    with open(executable, "rb") as f:
        elffile = ELFFile(f)

        symtab = elffile.get_section_by_name(".symtab")
        if symtab:
            for symbol in symtab.iter_symbols():
                if symbol["st_info"]["type"] == "STT_FUNC":
                    functions[symbol["st_value"]] = symbol.name

        dynsym = elffile.get_section_by_name(".dynsym")
        if dynsym:
            for symbol in dynsym.iter_symbols():
                if symbol["st_info"]["type"] == "STT_FUNC":
                    functions[symbol["st_value"]] = symbol.name

    return functions


def get_functions(instructions: Dict[str, List[Instruction]]):
    functions = {}

    function_symbols = get_function_symbols()
    sorted_addresses = sorted(function_symbols.keys())

    for section_name, section_instructions in instructions.items():
        if section_name == ".text":
            for function_address in sorted_addresses:
                function_name = function_symbols[function_address]

                # Find the function start
                function_start_index = None
                for i, instruction in enumerate(section_instructions):
                    if instruction.address == function_address:
                        function_start_index = i
                        break

                if function_start_index is None:
                    continue

                # Find the function end
                function_end_index = function_start_index
                for j in range(function_start_index, len(section_instructions)):
                    instruction = section_instructions[j]

                    # Hit another function
                    if instruction.address in function_symbols:
                        break

                    if instruction.mnemonic == "ret":
                        function_end_index = j
                        break

                function_instructions = section_instructions[
                    function_start_index : function_end_index + 1
                ]
                current_function = Function(
                    function_name, function_address, function_instructions
                )
                current_function.end_address = function_instructions[-1].address

                functions[function_name] = current_function

    return functions


def main():
    instructions = get_file_instructions(executable)
    relocations = get_file_relocations()
    strings = get_file_strings()
    translate_instructions(instructions, relocations, strings)
    write_to_file(
        executable,
        instructions,
    )
    functions = get_functions(instructions)
    print(functions)


if __name__ == "__main__":
    if len(sys.argv) == 2:
        executable = sys.argv[1]
        main()
