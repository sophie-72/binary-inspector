"""Represent a function."""

from typing import List

from src.control_flow_graph import identify_basic_blocks
from src.models.address import Address
from src.models.basic_block import BasicBlock
from src.models.instruction import Instruction


class Function:
    """Represent a function."""

    def __init__(
        self, name: str, start_address: Address, instructions: List[Instruction]
    ) -> None:
        self.__name = name
        self.__start_address = start_address
        self.__instructions = instructions
        self.__basic_blocks: List[BasicBlock] = []

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

    def analyze(self):
        """Analyze the function."""
        self.__basic_blocks = identify_basic_blocks(self.__instructions)
