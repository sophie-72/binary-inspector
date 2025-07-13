import unittest

from src.models import Instruction, BasicBlock, Address
from tests.fixtures import ANY_ADDRESS, ANY_OP_STR, ANY_MNEMONIC


class TestBasicBlock(unittest.TestCase):
    def setUp(self):
        self.any_end_address = Address(0x8)

    def test_given_instructions_when_created_then_end_address_is_last_instruction_address(
        self,
    ):
        instructions = [
            Instruction(
                address=ANY_ADDRESS,
                mnemonic=ANY_MNEMONIC,
                op_str=ANY_OP_STR,
            ),
            Instruction(
                address=self.any_end_address,
                mnemonic=ANY_MNEMONIC,
                op_str=ANY_OP_STR,
            ),
        ]
        block = BasicBlock(start_address=ANY_ADDRESS, instructions=instructions)

        end_address = block.end_address
        self.assertEqual(end_address, self.any_end_address)

    def test_given_no_instructions_when_created_then_end_address_is_start_address(self):
        block = BasicBlock(start_address=ANY_ADDRESS, instructions=[])

        end_address = block.end_address
        self.assertEqual(end_address, ANY_ADDRESS)

    def test_given_one_instruction_when_created_then_end_address_is_instruction_end_address(
        self,
    ):
        single_instruction = [
            Instruction(
                address=ANY_ADDRESS,
                mnemonic=ANY_MNEMONIC,
                op_str=ANY_OP_STR,
            )
        ]
        block = BasicBlock(start_address=ANY_ADDRESS, instructions=single_instruction)

        end_address = block.end_address
        self.assertEqual(end_address, ANY_ADDRESS)
