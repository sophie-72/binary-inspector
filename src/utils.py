"""Various functions used by different modules"""

from src.constants import RETURN_MNEMONIC
from src.models.instruction import Instruction


def is_block_terminator(instruction: Instruction):
    """
    Determine if the instruction is the last a block.
    :param instruction: The instruction
    :return: If the instruction represents a return or a jump
    """
    return instruction.mnemonic == RETURN_MNEMONIC or instruction.mnemonic.startswith(
        "j"
    )
