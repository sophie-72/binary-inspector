from typing import List, Dict, Optional

from blocks import identify_basic_blocks, is_block_terminator
from elf_utils import get_function_symbols
from models import Function, BasicBlock, Instruction


def print_main_function_graph(
    instructions: Dict[str, List[Instruction]], executable
) -> None:
    functions = _get_functions(instructions, executable)
    for function_name, function in functions.items():
        if function_name == "main":
            graph = _get_control_flow_graph(function)
            _print_control_flow_graph(function, graph)


def _get_functions(instructions: Dict[str, List[Instruction]], executable):
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
            identify_basic_blocks(current_function)

            functions[function_name] = current_function

    return functions


def _print_control_flow_graph(
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


def _get_control_flow_graph(function: Function) -> Dict[BasicBlock, List[BasicBlock]]:
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
            target_address = _extract_jump_target(last_instruction)
            if target_address:
                target_block = _find_block_by_address(
                    function.basic_blocks, target_address
                )
                if target_block and target_block not in graph[block]:
                    graph[block].append(target_block)

    return graph


def _extract_jump_target(instruction: Instruction) -> Optional[int]:
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


def _find_block_by_address(
    blocks: List[BasicBlock], target_address: int
) -> Optional[BasicBlock]:
    for block in blocks:
        if block.start_address <= target_address <= block.end_address:
            return block

    return None
