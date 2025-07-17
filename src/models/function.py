"""Represents a function."""

from typing import List, Optional

from src.constants import JUMP_MNEMONIC
from src.models.address import Address
from src.models.basic_block import BasicBlock
from src.models.instruction import Instruction
from src.utils import is_block_terminator


class Function:
    """Represents a function."""

    def __init__(
        self, name: str, start_address: Address, instructions: List[Instruction]
    ) -> None:
        self.__name = name
        self.__start_address = start_address
        self.__instructions = instructions
        self.__basic_blocks: List[BasicBlock] = []

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Function):
            return False

        return (
            self.name == other.name
            and self.start_address == other.start_address
            and self.instructions == other.instructions
            and self.basic_blocks == other.basic_blocks
        )

    @property
    def name(self) -> str:
        """Get the name of the function."""
        return self.__name

    @property
    def start_address(self) -> Address:
        """Get the start address of the function."""
        return self.__start_address

    @property
    def instructions(self) -> List[Instruction]:
        """Get the instructions of the function."""
        return self.__instructions

    @property
    def basic_blocks(self) -> List[BasicBlock]:
        """Get the basic blocks of the function."""
        return self.__basic_blocks

    def identify_basic_blocks(self) -> None:
        """Identify basic blocks in the function."""
        blocks = []
        current_block_instructions: List[Instruction] = []

        def append_block(instructions: List[Instruction]) -> None:
            if instructions:
                block = BasicBlock(current_block_instructions[0].address, instructions)
                blocks.append(block)

        for i, instruction in enumerate(self.instructions):
            current_block_instructions.append(instruction)

            if is_block_terminator(instruction) or _is_jump_target(
                self.instructions, i
            ):
                append_block(current_block_instructions)
                current_block_instructions = []

        append_block(current_block_instructions)
        self.__basic_blocks = blocks

    def identify_successors_and_predecessors(self) -> None:
        """Identify successors and predecessors of each basic block in the function."""
        for i, block in enumerate(self.basic_blocks):
            last_instruction = block.instructions[-1]

            if (
                last_instruction.mnemonic.startswith("j")
                and last_instruction.mnemonic != JUMP_MNEMONIC
            ) or not is_block_terminator(last_instruction):
                _add_next_block(self.basic_blocks, block, i)

            if last_instruction.mnemonic.startswith("j"):
                _add_jump_target(self.basic_blocks, block, last_instruction)


def _is_jump_target(instructions: List[Instruction], index: int):
    if index >= len(instructions):
        return False

    current_address = instructions[index].address

    for previous_instruction in instructions[:index]:
        if (
            previous_instruction.mnemonic.startswith("j")
            and "0x" in previous_instruction.op_str
        ):
            try:
                target = Address(int(previous_instruction.op_str.strip(), 16))
                if target == current_address:
                    return True
            except ValueError:
                pass

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
        if block.start_address.value <= target_address <= block.end_address.value:
            return block

    return None
