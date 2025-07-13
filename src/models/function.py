from src.models.address import Address
from src.types import InstructionList, BasicBlockList


class Function:
    """Represent a function."""

    def __init__(
        self, name: str, start_address: Address, instructions: InstructionList
    ) -> None:
        self.__name = name
        self.__start_address = start_address
        self.__instructions = instructions
        self.__basic_blocks: BasicBlockList = []

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
    def instructions(self) -> InstructionList:
        """Get the instructions of the function."""
        return self.__instructions

    @property
    def basic_blocks(self) -> BasicBlockList:
        """Get the basic blocks of the function."""
        return self.__basic_blocks

    @basic_blocks.setter
    def basic_blocks(self, basic_blocks: BasicBlockList) -> None:
        """Set the basic blocks of the function."""
        self.__basic_blocks = basic_blocks
