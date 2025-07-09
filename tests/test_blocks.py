import unittest

from src.blocks import is_block_terminator
from src.models import Instruction
from tests.fixtures import ANY_START_ADDRESS, ANY_OP_STR, ANY_MNEMONIC


class TestIsBlockTerminator(unittest.TestCase):
    def test_given_return_instruction_when_checking_if_block_terminator_then_true(self):
        return_mnemonic = "ret"
        instruction = Instruction(
            address=ANY_START_ADDRESS, mnemonic=return_mnemonic, op_str=ANY_OP_STR
        )

        result = is_block_terminator(instruction)

        self.assertTrue(result)

    def test_given_jump_instruction_when_checking_if_block_terminator_then_true(self):
        a_jump_mnemonic = "jmp"
        instruction = Instruction(
            address=ANY_START_ADDRESS, mnemonic=a_jump_mnemonic, op_str=ANY_OP_STR
        )

        result = is_block_terminator(instruction)

        self.assertTrue(result)

    def test_given_any_other_instruction_when_checking_if_block_terminator_then_false(
        self,
    ):
        instruction = Instruction(
            address=ANY_START_ADDRESS, mnemonic=ANY_MNEMONIC, op_str=ANY_OP_STR
        )

        result = is_block_terminator(instruction)

        self.assertFalse(result)
