from typing import Optional


class Instruction:
    def __init__(self, address, mnemonic, op_str) -> None:
        self.address: int = address
        self.mnemonic: str = mnemonic
        self.op_str: str = op_str
        self.translation: Optional[str] = None
