from typing import Optional, List


class Instruction:
    def __init__(self, address, mnemonic, op_str) -> None:
        self.address: int = address
        self.mnemonic: str = mnemonic
        self.op_str: str = op_str
        self.translation: Optional[str] = None


class BasicBlock:
    def __init__(self, start_address, instructions):
        self.start_address: int = start_address
        self.end_address = instructions[-1].address if instructions else start_address
        self.instructions: List[Instruction] = instructions


class Function:
    def __init__(self, name, start_address, instructions):
        self.name: str = name
        self.start_address: int = start_address
        self.instructions: List[Instruction] = instructions
        self.basic_blocks: List[BasicBlock] = []
