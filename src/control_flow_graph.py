"""Generate the control flow graph of the main function."""

from typing import Dict, Optional

from src.blocks import is_block_terminator
from src.constants import JUMP_MNEMONIC
from src.functions import identify_functions
from src.models import Function, BasicBlock, Instruction
from src.types import (
    SectionNameToInstructionsMapping,
    AddressToStringMapping,
    BasicBlockList,
)


def print_main_function_graph(
    instructions: SectionNameToInstructionsMapping,
    function_symbols: AddressToStringMapping,
) -> None:
    """
    Print the control flow graph elements of the main function.
    :param instructions: A dictionary mapping section names to lists of instructions.
    :param function_symbols: A dictionary mapping function addresses to function names.
    """
    functions = identify_functions(instructions, function_symbols)
    for function_name, function in functions.items():
        if function_name == "main":
            graph = _get_control_flow_graph(function)
            _print_control_flow_graph(function, graph)


def _print_control_flow_graph(
    function: Function, graph: Dict[BasicBlock, BasicBlockList]
) -> None:
    print(f"\nControl Flow Graph for {function.name}:")
    print("=" * 50)

    for i, block in enumerate(function.basic_blocks):
        successors = graph.get(block, [])

        print(
            f"Block {i}: "
            f"{block.start_address.to_hex_string()} - {block.end_address.to_hex_string()}"
        )
        print(f"  Instructions: {len(block.instructions)}")
        print(f"  Successors: {len(successors)}")

        for succ in successors:
            succ_index = function.basic_blocks.index(succ)
            print(f"    -> Block {succ_index} ({succ.start_address.to_hex_string()})")

        print()


def _get_control_flow_graph(function: Function) -> Dict[BasicBlock, BasicBlockList]:
    graph: Dict[BasicBlock, BasicBlockList] = {}

    for i, block in enumerate(function.basic_blocks):
        graph[block] = []
        last_instruction = block.instructions[-1]

        if (
            last_instruction.mnemonic.startswith("j")
            and last_instruction.mnemonic != JUMP_MNEMONIC
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
    blocks: BasicBlockList, target_address: int
) -> Optional[BasicBlock]:
    for block in blocks:
        if block.start_address.value <= target_address <= block.end_address.value:
            return block

    return None
