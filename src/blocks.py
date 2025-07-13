"""Identify basic blocks in a function."""

from src.models import Function, BasicBlock
from src.types import InstructionList
from src.utils import is_block_terminator


def identify_basic_blocks(function: Function) -> None:
    """
    Identify basic blocks in a function.
    :param function: The function
    """
    blocks = []
    current_block_instructions: InstructionList = []

    def append_block(instructions: InstructionList) -> None:
        if instructions:
            block = BasicBlock(current_block_instructions[0].address, instructions)
            blocks.append(block)

    for i, instruction in enumerate(function.instructions):
        current_block_instructions.append(instruction)

        if is_block_terminator(instruction) or _is_jump_target(
            function.instructions, i
        ):
            append_block(current_block_instructions)
            current_block_instructions = []

    append_block(current_block_instructions)
    function.basic_blocks = blocks


def _is_jump_target(instructions: InstructionList, index: int):
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
