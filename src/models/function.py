"""Represents a function."""

from typing import List

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

    @basic_blocks.setter
    def basic_blocks(self, basic_blocks: List[BasicBlock]) -> None:
        """Set the basic blocks of the function."""
        self.__basic_blocks = basic_blocks

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
        self.basic_blocks = blocks


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
                target = Address(int(previous_instruction.op_str.strip(), 16))
                if target == next_address:
                    return True
            except ValueError:
                pass

    return False
