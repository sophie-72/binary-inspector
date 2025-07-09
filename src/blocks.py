"""Identify basic blocks in a function."""

from typing import List

from src.models import Instruction, Function, BasicBlock
from src.utils import is_block_terminator


def identify_basic_blocks(function: Function) -> None:
    """
    Identify basic blocks in a function.
    :param function: the function
    """
    blocks: List[BasicBlock] = []
    current_block_instructions: List[Instruction] = []

    for i, instruction in enumerate(function.instructions):
        current_block_instructions.append(instruction)

        if (
            is_block_terminator(instruction)
            or _is_jump_target(function.instructions, i)
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


def _is_jump_target(instructions: List[Instruction], index: int):
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
