"""Models used for the analysis."""

from typing import Optional, List


class Address:
    """Represents an address."""

    def __init__(self, value: int) -> None:
        self.__value = value

    def __eq__(self, other) -> bool:
        if not isinstance(other, Address):
            return False

        return self.__value == other.value

    def __hash__(self) -> int:
        return hash(self.__value)

    @property
    def value(self) -> int:
        """Get the address value."""
        return self.__value

    def to_hex_string(self) -> str:
        """Convert the address to a hex string."""
        return hex(self.__value)


class Instruction:
    """Represent an assembly instruction."""

    def __init__(self, address: Address, mnemonic: str, op_str: str) -> None:
        self.__address = address
        self.__mnemonic = mnemonic
        self.__op_str = op_str
        self.__translation: Optional[str] = None

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Instruction):
            return False

        return (
            self.address == other.address
            and self.mnemonic == other.mnemonic
            and self.op_str == other.op_str
        )

    @property
    def address(self) -> Address:
        """Get the address of the instruction."""
        return self.__address

    @property
    def mnemonic(self) -> str:
        """Get the mnemonic of the instruction."""
        return self.__mnemonic

    @property
    def op_str(self) -> str:
        """Get the operand string of the instruction."""
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

    def __init__(self, start_address: Address, instructions: List[Instruction]) -> None:
        self.__start_address = start_address
        self.__end_address = instructions[-1].address if instructions else start_address
        self.__instructions = instructions

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, BasicBlock):
            return False

        return (
            self.__start_address == other.__start_address
            and self.__end_address == other.__end_address
            and self.__instructions == other.__instructions
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


class Function:
    """Represent a function."""

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
