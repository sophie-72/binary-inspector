from typing import List

from src.models import Instruction
from src.models.address import Address


class BasicBlock:
    """Represent a basic block."""

    def __init__(self, start_address: Address, instructions: List[Instruction]) -> None:
        self.__start_address = start_address
        self.__end_address = instructions[-1].address if instructions else start_address
        self.__instructions = instructions

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, BasicBlock):
            return False

        return (
            self.start_address == other.start_address
            and self.end_address == other.end_address
            and self.instructions == other.instructions
        )

    def __hash__(self) -> int:
        return hash(self.__start_address)

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
