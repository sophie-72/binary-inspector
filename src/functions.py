"""Identify functions from instructions and function symbols."""

from typing import Dict

from src.blocks import identify_basic_blocks
from src.constants import RETURN_MNEMONIC
from src.models import Function, Address
from src.types import (
    SectionNameToInstructionsMapping,
    AddressToStringMapping,
    InstructionList,
)


def identify_functions(
    instructions: SectionNameToInstructionsMapping,
    function_symbols: AddressToStringMapping,
) -> Dict[str, Function]:
    """
    Identify functions from instructions and function symbols.
    :param instructions: A dictionary mapping section names to lists of instructions.
    :param function_symbols: A dictionary mapping function addresses to function names.
    :return: A dictionary mapping function names to function objects.
    """
    functions = {}

    sorted_addresses = sorted(function_symbols.keys(), key=lambda x: x.value)

    for section_instructions in instructions.values():
        for function_address in sorted_addresses:
            function_name = function_symbols[function_address]

            function_start_index = _get_function_start_index(
                section_instructions, function_address
            )

            if function_start_index is not None:
                function_end_index = _get_function_end_index(
                    function_start_index,
                    section_instructions,
                    function_symbols,
                    function_address,
                )

                function_instructions = section_instructions[
                    function_start_index : function_end_index + 1
                ]
                current_function = Function(
                    function_name, function_address, function_instructions
                )
                identify_basic_blocks(current_function)

                functions[function_name] = current_function

    return functions


def _get_function_start_index(
    section_instructions: InstructionList, function_address: Address
):
    function_start_index = None
    for i, instruction in enumerate(section_instructions):
        if instruction.address == function_address:
            function_start_index = i
            break

    return function_start_index


def _get_function_end_index(
    function_start_index: int,
    section_instructions: InstructionList,
    function_symbols: AddressToStringMapping,
    function_address: Address,
):
    function_end_index = function_start_index
    for j in range(function_start_index + 1, len(section_instructions)):
        instruction = section_instructions[j]

        # Stop if we hit another function
        if (
            instruction.address in function_symbols
            and instruction.address != function_address
        ):
            break

        function_end_index = j
        if instruction.mnemonic == RETURN_MNEMONIC:
            break

    return function_end_index
