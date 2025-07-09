from src.models import Instruction


def is_block_terminator(instruction: Instruction):
    """
    Determine if the instruction is the last a block.
    :param instruction: the instruction
    :return: if the instruction represents a return or a jump
    """
    return instruction.mnemonic == "ret" or instruction.mnemonic.startswith("j")
