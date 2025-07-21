"""Translate assembly instructions into a more readable format."""

import re

from src.constants import HEX_ADDRESS_MATCH_PATTERN
from src.models import Instruction, Address
from src.custom_types import (
    SectionNameToInstructionsMapping,
    InstructionList,
    AddressToStringMapping,
)


def translate_instructions(
    instructions: SectionNameToInstructionsMapping,
    relocations: AddressToStringMapping,
    function_symbols: AddressToStringMapping,
    strings: AddressToStringMapping,
) -> None:
    """
    Translate some instructions into a more readable format.
    :param instructions: A dictionary mapping section names to lists of instructions.
    :param relocations: A dictionary mapping relocation addresses to symbols.
    :param function_symbols: A dictionary mapping function addresses to function names.
    :param strings: A dictionary mapping string addresses to strings.
    """
    for section_instructions in instructions.values():
        for instruction in section_instructions:
            _translate_instruction(
                instruction,
                section_instructions,
                relocations,
                function_symbols,
                strings,
            )


def _translate_instruction(
    instruction: Instruction,
    instructions: InstructionList,
    relocations: AddressToStringMapping,
    function_symbols: AddressToStringMapping,
    strings: AddressToStringMapping,
) -> None:
    line_before_translation = instruction.mnemonic + " " + instruction.op_str
    line = line_before_translation
    line = _translate_pointer(line)
    line = _translate_rip(line, instructions, instruction)
    line = _evaluate_addition(line)
    line = _translate_relocation(line, relocations)
    line = _translate_function_call(line, function_symbols)
    line = _translate_strings(line, strings)

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
        line = line.replace(rip_keyword, next_instruction_addr.to_hex_string())

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


def _translate_relocation(line, relocations):
    memory = re.search(f"memory\\[{HEX_ADDRESS_MATCH_PATTERN}+]", line)
    if memory:
        hex_address = re.search(HEX_ADDRESS_MATCH_PATTERN, memory.group())
        if hex_address:
            address = Address(int(hex_address.group(), 16))
            function_name = relocations.get(address)

            if function_name:
                line = line.replace(memory.group(), function_name)

    return line


def _translate_function_call(line, function_symbols):
    if "call" in line:
        hex_address = re.search(HEX_ADDRESS_MATCH_PATTERN, line)
        if hex_address:
            address = Address(int(hex_address.group(), 16))
            function_name = function_symbols.get(address)

            if function_name:
                line = line.replace(hex_address.group(), function_name)

    return line


def _translate_strings(line, strings):
    address_string = re.search(HEX_ADDRESS_MATCH_PATTERN, line)
    if address_string:
        address = Address(int(address_string.group(), 16))
        string = strings.get(address)

        if string:
            line = line.replace(address_string.group(), '"' + string + '"')

    return line
