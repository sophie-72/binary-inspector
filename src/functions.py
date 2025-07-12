"""Identify functions from instructions and function symbols."""

from typing import Dict, List

from src.blocks import identify_basic_blocks
from src.models import Instruction, Function


def identify_functions(
    instructions: Dict[str, List[Instruction]], function_symbols: Dict[int, str]
) -> Dict[str, Function]:
    """
    Identify functions from instructions and function symbols.
    :param instructions: dictionary mapping section names and list of instructions
    :param function_symbols: dictionary mapping function addresses to function names
    :return: dictionary mapping function addresses to function objects
    """
    functions = {}

    sorted_addresses = sorted(function_symbols.keys())

    for section_instructions in instructions.values():
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
            identify_basic_blocks(current_function)

            functions[function_name] = current_function

    return functions
