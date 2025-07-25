import unittest

from src.constants import JUMP_MNEMONIC, RETURN_MNEMONIC
from src.utils import is_block_terminator
from src.models.instruction import Instruction
from tests.fixtures import ANY_ADDRESS, ANY_OP_STR, ANY_MNEMONIC


class TestIsBlockTerminator(unittest.TestCase):
    def test_return_instruction_is_block_terminator(self):
        instruction = Instruction(
            address=ANY_ADDRESS, mnemonic=RETURN_MNEMONIC, op_str=ANY_OP_STR
        )

        result = is_block_terminator(instruction)

        self.assertTrue(result)

    def test_jump_instruction_is_block_terminator_(self):
        instruction = Instruction(
            address=ANY_ADDRESS, mnemonic=JUMP_MNEMONIC, op_str=ANY_OP_STR
        )

        result = is_block_terminator(instruction)

        self.assertTrue(result)

    def test_any_other_instruction_is_not_block_terminator(
        self,
    ):
        instruction = Instruction(
            address=ANY_ADDRESS, mnemonic=ANY_MNEMONIC, op_str=ANY_OP_STR
        )

        result = is_block_terminator(instruction)

        self.assertFalse(result)
