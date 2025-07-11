import unittest

from src.blocks import identify_basic_blocks
from src.models import Function, Instruction
from tests.fixtures import ANY_ADDRESS, ANY_MNEMONIC, ANY_OP_STR

ANY_FUNCTION_NAME = "function name"


class TestIdentifyBasicBlocks(unittest.TestCase):
    def test_identify_basic_blocks(self):
        jump_mnemonic = "jmp"
        return_mnemonic = "ret"
        instructions = [
            Instruction(address=0x1000, mnemonic=ANY_MNEMONIC, op_str=ANY_OP_STR),
            Instruction(address=0x1001, mnemonic=jump_mnemonic, op_str=ANY_OP_STR),
            Instruction(address=0x1002, mnemonic=ANY_MNEMONIC, op_str=ANY_OP_STR),
            Instruction(address=0x1003, mnemonic=return_mnemonic, op_str=ANY_OP_STR),
        ]
        function = Function(
            name=ANY_FUNCTION_NAME,
            start_address=ANY_ADDRESS,
            instructions=instructions,
        )

        identify_basic_blocks(function)

        self.assertEqual(len(function.basic_blocks), 2)
        self.assertEqual(function.basic_blocks[0].start_address, 0x1000)
        self.assertEqual(function.basic_blocks[1].start_address, 0x1002)
