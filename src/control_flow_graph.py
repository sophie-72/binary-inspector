"""Generate the control flow graph of the main function."""

from typing import Dict, Optional, List

from src.blocks import is_block_terminator
from src.constants import JUMP_MNEMONIC
from src.models import Function, BasicBlock, Instruction
from src.types import (
    BasicBlockList,
    FunctionNameToFunctionMapping,
)


def print_main_function_graph(
    functions: FunctionNameToFunctionMapping,
) -> None:
    """
    Print the control flow graph elements of the main function.
    :param functions: A dictionary mapping function names to functions.
    """
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
        print(f"  Predecessors: {len(block.predecessors)}")

        for succ in successors:
            succ_index = function.basic_blocks.index(succ)
            print(f"    -> Block {succ_index} ({succ.start_address.to_hex_string()})")

        for pred in block.predecessors:
            pred_index = function.basic_blocks.index(pred)
            print(f"    <- Block {pred_index} ({pred.start_address.to_hex_string()})")

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
            _add_next_block(graph, function.basic_blocks, block, i)

        if last_instruction.mnemonic.startswith("j"):
            _add_jump_target(graph, function.basic_blocks, block, last_instruction)

    return graph


def _add_next_block(
    graph: Dict[BasicBlock, BasicBlockList],
    basic_blocks: List[BasicBlock],
    block: BasicBlock,
    index: int,
):
    if index + 1 < len(basic_blocks):
        graph[block].append(basic_blocks[index + 1])


def _add_jump_target(
    graph: Dict[BasicBlock, BasicBlockList],
    basic_blocks: List[BasicBlock],
    block: BasicBlock,
    instruction: Instruction,
):
    target_address = _extract_jump_target(instruction)
    if target_address:
        target_block = _find_block_by_address(basic_blocks, target_address)
        if target_block and target_block not in graph[block]:
            graph[block].append(target_block)
            block.add_successor(target_block)
            target_block.add_predecessor(block)


def _extract_jump_target(instruction: Instruction) -> Optional[int]:
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
