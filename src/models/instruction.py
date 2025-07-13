"""Represents an assembly instruction."""

from typing import Optional

from src.models.address import Address


class Instruction:
    """Represents an assembly instruction."""

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
