from typing import List

from models import Instruction, Function, BasicBlock


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
