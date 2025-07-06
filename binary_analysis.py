import sys
from typing import List, Dict, Optional

from elf_utils import (
    get_function_symbols,
    get_file_instructions,
    get_file_relocations,
    get_file_strings,
)
from models import Instruction, Function, BasicBlock
from translation import translate_instructions


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


def get_functions(instructions: Dict[str, List[Instruction]]):
    functions = {}

    function_symbols = get_function_symbols(executable)
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

        if (
            last_instruction.mnemonic.startswith("j")
            and last_instruction.mnemonic != "jmp"
        ) or not is_block_terminator(last_instruction):
            if i + 1 < len(function.basic_blocks):
                graph[block].append(function.basic_blocks[i + 1])

        if last_instruction.mnemonic.startswith("j"):
            target_address = extract_jump_target(last_instruction)
            if target_address:
                target_block = find_block_by_address(
                    function.basic_blocks, target_address
                )
                if target_block and target_block not in graph[block]:
                    graph[block].append(target_block)

    return graph


def print_control_flow_graph(
    function: Function, graph: Dict[BasicBlock, List[BasicBlock]]
) -> None:
    print(f"\nControl Flow Graph for {function.name}:")
    print("=" * 50)

    for i, block in enumerate(function.basic_blocks):
        successors = graph.get(block, [])

        print(f"Block {i}: 0x{block.start_address:x} - 0x{block.end_address:x}")
        print(f"  Instructions: {len(block.instructions)}")
        print(f"  Successors: {len(successors)}")

        for j, succ in enumerate(successors):
            succ_index = function.basic_blocks.index(succ)
            print(f"    -> Block {succ_index} (0x{succ.start_address:x})")

        print()


def main():
    instructions = get_file_instructions(executable)
    relocations = get_file_relocations(executable)
    strings = get_file_strings(executable)
    translate_instructions(instructions, relocations, strings)
    write_to_file(executable, instructions)

    functions = get_functions(instructions)
    for function_name, function in functions.items():
        if function_name == "main":
            graph = get_control_flow_graph(function)
            print_control_flow_graph(function, graph)


if __name__ == "__main__":
    if len(sys.argv) == 2:
        executable = sys.argv[1]
        main()
