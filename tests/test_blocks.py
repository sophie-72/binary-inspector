import unittest

from src.blocks import identify_basic_blocks
from src.models import Function, Instruction
from tests.fixtures import ANY_ADDRESS, ANY_MNEMONIC, ANY_OP_STR


class TestIdentifyBasicBlocks(unittest.TestCase):
    def test_given_function_with_multiple_instructions_when_identifying_basic_blocks_then_blocks_correctly_identified(  # pylint: disable=line-too-long
        self,
    ):
        any_function_name = "function name"
        instructions = [
            Instruction(address=0x1000, mnemonic=ANY_MNEMONIC, op_str=ANY_OP_STR),
            Instruction(address=0x1001, mnemonic="jmp", op_str=ANY_OP_STR),
            Instruction(address=0x1002, mnemonic=ANY_MNEMONIC, op_str=ANY_OP_STR),
            Instruction(address=0x1003, mnemonic="ret", op_str=ANY_OP_STR),
        ]
        function = Function(
            name=any_function_name,
            start_address=ANY_ADDRESS,
            instructions=instructions,
        )

        identify_basic_blocks(function)

        self.assertEqual(len(function.basic_blocks), 2)
        self.assertEqual(function.basic_blocks[0].start_address, 0x1000)
        self.assertEqual(function.basic_blocks[1].start_address, 0x1002)
