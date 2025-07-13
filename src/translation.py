"""Translate assembly instructions into a more readable format."""

import re

from src.models import Instruction
from src.types import (
    SectionNameToInstructionsMapping,
    InstructionList,
    AddressToStringMapping,
)

HEX_ADDRESS_MATCH_PATTERN = "0x[0-9a-f]+"


def translate_instructions(
    instructions: SectionNameToInstructionsMapping,
    relocations: AddressToStringMapping,
    strings: AddressToStringMapping,
) -> None:
    """
    Translate some instructions into a more readable format.
    :param instructions: A dictionary mapping section names to lists of instructions.
    :param relocations: A dictionary mapping relocation addresses to symbols.
    :param strings: A dictionary mapping string addresses to strings.
    """
    for section_instructions in instructions.values():
        for instruction in section_instructions:
            _translate_instruction(
                instruction, section_instructions, relocations, strings
            )


def _translate_instruction(
    instruction: Instruction,
    instructions: InstructionList,
    relocations: AddressToStringMapping,
    strings: AddressToStringMapping,
) -> None:
    line_before_translation = instruction.mnemonic + " " + instruction.op_str
    line = line_before_translation
    line = _translate_pointer(line)
    line = _translate_rip(line, instructions, instruction)
    line = _evaluate_addition(line)
    line = _translate_function_name(line, relocations)
    line = _translate_strings(line, strings)
    line = _translate_printable_character(line)

    if line != line_before_translation:
        instruction.translation = line


def _translate_pointer(line):
    pointer_types = ["qword", "byte"]

    for pointer_type in pointer_types:
        line = line.replace(f"{pointer_type} ptr [", "memory[")

    return line


def _translate_rip(line, instructions, i):
    rip_keyword = "rip"
    if rip_keyword in line:
        next_instruction = instructions[instructions.index(i) + 1]
        next_instruction_addr = next_instruction.address
        line = line.replace(rip_keyword, hex(next_instruction_addr))

    return line


def _evaluate_addition(line):
    hex_addition = re.search(
        f"{HEX_ADDRESS_MATCH_PATTERN}\\s\\+\\s{HEX_ADDRESS_MATCH_PATTERN}", line
    )
    if hex_addition:
        elements = re.findall(HEX_ADDRESS_MATCH_PATTERN, hex_addition.group())
        left = int(elements[0], 16)
        right = int(elements[1], 16)
        result = left + right
        line = line.replace(hex_addition.group(), hex(result))

    return line


def _translate_function_name(line, relocations):
    memory = re.search(f"memory\\[{HEX_ADDRESS_MATCH_PATTERN}+]", line)
    if memory:
        hex_address = re.search(HEX_ADDRESS_MATCH_PATTERN, memory.group())
        if hex_address:
            function_name = relocations.get(hex_address.group())

            if function_name:
                line = line.replace(memory.group(), function_name)

    return line


def _translate_strings(line, strings):
    address = re.search(HEX_ADDRESS_MATCH_PATTERN, line)
    if address:
        string = strings.get(address.group())

        if string:
            line = line.replace(address.group(), '"' + string + '"')

    return line


def _translate_printable_character(line):
    range_min = 32
    range_max = 126
    hex_character = re.search("0x[0-9a-f]{2}$", line)
    if hex_character:
        decimal_value = int(hex_character.group(), 16)

        if range_min <= decimal_value <= range_max:
            character = chr(decimal_value)
            line = line.replace(hex_character.group(), character)

    return line
