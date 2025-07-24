"""Build the control flow graph from an instruction list."""

import re
from typing import List, Optional

from src.constants import JUMP_MNEMONIC, HEX_ADDRESS_MATCH_PATTERN
from src.models.address import Address
from src.models.basic_block import BasicBlock
from src.models.instruction import Instruction
from src.utils import is_block_terminator


def identify_basic_blocks(instructions: List[Instruction]) -> List[BasicBlock]:
    """
    Identify basic blocks in the instruction list.
    :param instructions: The instruction list.
    :return: The list of basic blocks identified from the instruction list.
    """
    blocks = _create_basic_blocks_from_instruction_list(instructions)
    _identify_successors_and_predecessors(blocks)
    return blocks


def _create_basic_blocks_from_instruction_list(instructions: List[Instruction]):
    blocks = []
    current_block_instructions: List[Instruction] = []

    def append_block(current_instructions: List[Instruction]) -> None:
        if current_instructions:
            block = BasicBlock(
                current_block_instructions[0].address, current_instructions
            )
            blocks.append(block)

    for i, instruction in enumerate(instructions):
        current_block_instructions.append(instruction)

        if is_block_terminator(instruction) or _is_jump_target(instructions, i):
            append_block(current_block_instructions)
            current_block_instructions = []

    append_block(current_block_instructions)
    return blocks


def _identify_successors_and_predecessors(basic_blocks: List[BasicBlock]) -> None:
    for i, block in enumerate(basic_blocks):
        last_instruction = block.instructions[-1]

        if (
            last_instruction.mnemonic.startswith("j")
            and last_instruction.mnemonic != JUMP_MNEMONIC
        ) or not is_block_terminator(last_instruction):
            _add_next_block(basic_blocks, block, i)

        if last_instruction.mnemonic.startswith("j"):
            _add_jump_target(basic_blocks, block, last_instruction)


def _is_jump_target(instructions: List[Instruction], index: int):
    current_address = instructions[index].address

    for previous_instruction in instructions[:index]:
        previous_instruction_hex_address = re.search(
            HEX_ADDRESS_MATCH_PATTERN, previous_instruction.op_str
        )
        if (
            previous_instruction.mnemonic.startswith("j")
            and previous_instruction_hex_address
        ):
            target = Address.from_hex_string(previous_instruction_hex_address.group())
            if target == current_address:
                return True

    return False


def _add_next_block(
    basic_blocks: List[BasicBlock], block: BasicBlock, index: int
) -> None:
    if index + 1 < len(basic_blocks):
        block.add_successor(basic_blocks[index + 1])
        basic_blocks[index + 1].add_predecessor(block)


def _add_jump_target(
    basic_blocks: List[BasicBlock], block: BasicBlock, instruction: Instruction
) -> None:
    target_address = _extract_jump_target(instruction)
    if target_address:
        target_block = _find_block_by_address(basic_blocks, target_address)
        if target_block:
            block.add_successor(target_block)
            target_block.add_predecessor(block)


def _extract_jump_target(instruction: Instruction) -> Optional[int]:
    op_str = instruction.op_str.strip()
    hex_address = re.search(HEX_ADDRESS_MATCH_PATTERN, op_str)

    if hex_address:
        return int(hex_address.group(), 16)

    return None


def _find_block_by_address(
    blocks: List[BasicBlock], target_address: int
) -> Optional[BasicBlock]:
    for block in blocks:
        if block.start_address.value <= target_address <= block.end_address.value:
            return block

    return None
