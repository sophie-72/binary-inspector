import re
import sys
from typing import List, Dict, Optional

from capstone import *
from elftools.elf.elffile import ELFFile

from models import Instruction, Function, BasicBlock
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
        for function_address in sorted_addresses:
            function_name = function_symbols[function_address]

            # Find the function start
            function_start_index = None
            for i, instruction in enumerate(section_instructions):
                if instruction.address == function_address:
                    function_start_index = i
                    break

            if function_start_index is None:
                continue  # Function not in this section

            # Find the function end
            function_end_index = function_start_index
            for j in range(function_start_index + 1, len(section_instructions)):
                instruction = section_instructions[j]

                # Stop if we hit another function or ret
                if (
                    instruction.address in function_symbols
                    and instruction.address != function_address
                ) or instruction.mnemonic == "ret":
                    break

                function_end_index = j

            function_instructions = section_instructions[
                function_start_index : function_end_index + 1
            ]
            current_function = Function(
                function_name, function_address, function_instructions
            )
            current_function.end_address = function_instructions[-1].address
            identify_basic_blocks(current_function)

            functions[function_name] = current_function

    return functions


def identify_basic_blocks(function: Function) -> None:
    blocks: List[BasicBlock] = []
    current_block_instructions: List[Instruction] = []

    for i, instruction in enumerate(function.instructions):
        current_block_instructions.append(instruction)

        if (
            is_block_terminator(instruction) or is_jump_target(function.instructions, i)
        ) and current_block_instructions:
            block = BasicBlock(
                current_block_instructions[0].address, current_block_instructions
            )
            blocks.append(block)
            current_block_instructions = []

    if current_block_instructions:
        block = BasicBlock(
            current_block_instructions[0].address, current_block_instructions
        )
        blocks.append(block)

    function.basic_blocks = blocks


def is_block_terminator(instruction: Instruction):
    return instruction.mnemonic == "ret" or instruction.mnemonic.startswith("j")


def is_jump_target(instructions: List[Instruction], index: int):
    if index + 1 >= len(instructions):
        return False

    next_address = instructions[index + 1].address

    for previous_instruction in instructions[: index + 1]:
        if (
            previous_instruction.mnemonic.startswith("j")
            and "0x" in previous_instruction.op_str
        ):
            try:
                target = int(previous_instruction.op_str.strip(), 16)
                if target == next_address:
                    return True
            except ValueError:
                pass

    return False


def extract_jump_target(instruction: Instruction) -> Optional[int]:
    if not instruction.mnemonic.startswith("j"):
        return None

    op_str = instruction.op_str.strip()

    if "0x" in op_str:
        try:
            target = int(op_str, 16)
            return target
        except ValueError:
            pass

    return None


def find_block_by_address(
    blocks: List[BasicBlock], target_address: int
) -> Optional[BasicBlock]:
    for block in blocks:
        if block.start_address <= target_address <= block.end_address:
            return block

    return None


def get_control_flow_graph(function: Function) -> Dict[BasicBlock, List[BasicBlock]]:
    graph = {}

    for i, block in enumerate(function.basic_blocks):
        graph[block] = []
        last_instruction = block.instructions[-1]

        if not is_block_terminator(last_instruction) and i + 1 < len(
            function.basic_blocks
        ):
            graph[block].append(function.basic_blocks[i + 1])

        if last_instruction.mnemonic.startswith("j"):
            target_address = extract_jump_target(last_instruction)
            if target_address:
                target_block = find_block_by_address(
                    function.basic_blocks, target_address
                )
                if target_block:
                    graph[block].append(target_block)

    return graph


def main():
    instructions = get_file_instructions(executable)
    relocations = get_file_relocations()
    strings = get_file_strings()
    translate_instructions(instructions, relocations, strings)
    write_to_file(executable, instructions)

    functions = get_functions(instructions)
    for function_name, function in functions.items():
        print(function_name)
        graph = get_control_flow_graph(function)
        print(graph)


if __name__ == "__main__":
    if len(sys.argv) == 2:
        executable = sys.argv[1]
        main()
