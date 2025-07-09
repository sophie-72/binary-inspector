import unittest

from src.models import Instruction, BasicBlock


class TestBasicBlock(unittest.TestCase):
    def setUp(self):
        self.any_mnemonic = "mov"
        self.any_op_str = "rbp, rsp"
        self.any_start_address = 0x4
        self.any_end_address = 0x8

    def test_given_instructions_when_created_then_end_address_is_last_instruction_address(
        self,
    ):
        instructions = [
            Instruction(self.any_start_address, self.any_mnemonic, self.any_op_str),
            Instruction(self.any_end_address, self.any_mnemonic, self.any_op_str),
        ]
        block = BasicBlock(
            start_address=self.any_start_address, instructions=instructions
        )

        end_address = block.end_address
        self.assertEqual(end_address, self.any_end_address)

    def test_given_no_instructions_when_created_then_end_address_is_start_address(self):
        block = BasicBlock(start_address=self.any_start_address, instructions=[])

        end_address = block.end_address

        self.assertEqual(end_address, self.any_start_address)

    def test_given_one_instruction_when_created_then_end_address_is_instruction_end_address(
        self,
    ):
        single_instruction = [
            Instruction(self.any_start_address, self.any_mnemonic, self.any_op_str)
        ]
        block = BasicBlock(
            start_address=self.any_start_address, instructions=single_instruction
        )
        end_address = block.end_address
        self.assertEqual(end_address, self.any_start_address)
