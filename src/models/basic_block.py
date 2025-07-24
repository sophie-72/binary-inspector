"""Represent a basic block."""

from typing import List


from src.models.address import Address
from src.models.instruction import Instruction


class BasicBlock:
    """Represent a basic block."""

    def __init__(self, start_address: Address, instructions: List[Instruction]) -> None:
        self.__start_address = start_address
        self.__end_address = instructions[-1].address if instructions else start_address
        self.__instructions = instructions
        self.__successors: List[BasicBlock] = []
        self.__predecessors: List[BasicBlock] = []

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, BasicBlock):
            return False

        return (
            self.start_address == other.start_address
            and self.end_address == other.end_address
            and self.instructions == other.instructions
        )

    @property
    def start_address(self) -> Address:
        """Get the start address of the basic block."""
        return self.__start_address

    @property
    def end_address(self) -> Address:
        """Get the end address of the basic block."""
        return self.__end_address

    @property
    def instructions(self) -> List[Instruction]:
        """Get the instructions of the basic block."""
        return self.__instructions

    @property
    def successors(self) -> List["BasicBlock"]:
        """Get the successors of the basic block."""
        return self.__successors

    @property
    def predecessors(self) -> List["BasicBlock"]:
        """Get the predecessors of the basic block."""
        return self.__predecessors

    def add_successor(self, successor: "BasicBlock") -> None:
        """Add a successor to the basic block."""
        self.__successors.append(successor)

    def add_predecessor(self, predecessor: "BasicBlock") -> None:
        """Add a predecessor to the basic block."""
        self.__predecessors.append(predecessor)
