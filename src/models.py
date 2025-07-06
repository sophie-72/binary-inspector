from typing import Optional, List


class Instruction:
    def __init__(self, address: int, mnemonic: str, op_str: str) -> None:
        self.address = address
        self.mnemonic = mnemonic
        self.op_str = op_str
        self.translation: Optional[str] = None


class BasicBlock:
    def __init__(self, start_address: int, instructions: List[Instruction]) -> None:
        self.start_address = start_address
        self.end_address = instructions[-1].address if instructions else start_address
        self.instructions = instructions


class Function:
    def __init__(
        self, name: str, start_address: int, instructions: List[Instruction]
    ) -> None:
        self.name = name
        self.start_address = start_address
        self.instructions = instructions
        self.basic_blocks: List[BasicBlock] = []
