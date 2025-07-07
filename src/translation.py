"""Translate assembly instructions into a more readable format."""

import re
from typing import List, Dict

from models import Instruction


def translate_instructions(
    instructions: Dict[str, List[Instruction]],
    relocations: Dict[str, str],
    strings: Dict[str, str],
) -> None:
    """
    Translate some instructions into a more readable format.
    :param instructions: dictionary of instructions by section
    :param relocations: dictionary of symbol for each relocation address
    :param strings: dictionary of string for each string address
    """
    for section_instructions in instructions.values():
        for instruction in section_instructions:
            _translate_instruction(
                instruction, section_instructions, relocations, strings
            )


def _translate_instruction(
    instruction: Instruction,
    instructions: List[Instruction],
    relocations: dict,
    strings: dict,
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
    if "qword ptr [" in line:
        line = line.replace("qword ptr [", "memory[")

    if "byte ptr [" in line:
        line = line.replace("byte ptr [", "memory[")

    return line


def _translate_rip(line, instructions, i):
    if "rip" in line:
        next_instruction = instructions[instructions.index(i) + 1]
        next_instruction_addr = next_instruction.address
        line = line.replace("rip", hex(next_instruction_addr))

    return line


def _evaluate_addition(line):
    hex_addition = re.search("0x[0-9a-f]+\\s\\+\\s0x[0-9a-f]+", line)
    if hex_addition:
        elements = re.findall("0x[0-9a-f]+", hex_addition.group())
        left = int(elements[0], 16)
        right = int(elements[1], 16)
        result = left + right
        line = line.replace(hex_addition.group(), hex(result))

    return line


def _translate_function_name(line, relocations):
    hex_address_match_pattern = "0x[0-9a-f]+"
    memory = re.search(f"memory\\[{hex_address_match_pattern}+]", line)
    if memory:
        hex_address = re.search(hex_address_match_pattern, memory.group())
        if hex_address:
            function_name = relocations.get(hex_address.group())

            if function_name:
                line = line.replace(memory.group(), function_name)

    return line


def _translate_strings(line, strings):
    hex_address_match_pattern = "0x[0-9a-f]+"
    address = re.search(hex_address_match_pattern, line)
    if address:
        string = strings.get(address.group())

        if string:
            line = line.replace(address.group(), '"' + string + '"')

    return line


def _translate_printable_character(line):
    hex_character = re.search("0x[0-9a-f]{2}$", line)
    if hex_character:
        decimal_value = int(hex_character.group(), 16)

        if 32 <= decimal_value <= 126:
            character = chr(decimal_value)
            line = line.replace(hex_character.group(), character)

    return line
