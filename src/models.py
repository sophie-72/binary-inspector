"""Models used for the analysis."""

from typing import Optional, List


class Instruction:
    """Represent an assembly instruction."""

    def __init__(self, address: int, mnemonic: str, op_str: str) -> None:
        self.__address = address
        self.__mnemonic = mnemonic
        self.__op_str = op_str
        self.__translation: Optional[str] = None

    @property
    def address(self) -> int:
        """Get the address of the instruction."""
        return self.__address

    @property
    def mnemonic(self) -> str:
        """Get the mnemonic of the instruction."""
        return self.__mnemonic

    @property
    def op_str(self) -> str:
        """Get the opcode of the instruction."""
        return self.__op_str

    @property
    def translation(self) -> Optional[str]:
        """Get the translation of the instruction."""
        return self.__translation

    @translation.setter
    def translation(self, translation: str) -> None:
        """Set the translation of the instruction."""
        self.__translation = translation


class BasicBlock:
    """Represent a basic block."""

    def __init__(self, start_address: int, instructions: List[Instruction]) -> None:
        self.__start_address = start_address
        self.__end_address = instructions[-1].address if instructions else start_address
        self.__instructions = instructions

    @property
    def start_address(self) -> int:
        """Get the start address of the basic block."""
        return self.__start_address

    @property
    def end_address(self) -> int:
        """Get the end address of the basic block."""
        return self.__end_address

    @property
    def instructions(self) -> List[Instruction]:
        """Get the instructions of the basic block."""
        return self.__instructions


class Function:
    """Represent a function."""

    def __init__(
        self, name: str, start_address: int, instructions: List[Instruction]
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
    def start_address(self) -> int:
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
