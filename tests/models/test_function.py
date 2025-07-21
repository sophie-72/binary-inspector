import unittest

from src.constants import RETURN_MNEMONIC
from src.models import Function, Address, Instruction
from tests.fixtures import (
    ANY_ADDRESS,
    A_FUNCTION_NAME,
    AN_INSTRUCTION_LIST,
    ANY_OP_STR,
    ANY_MNEMONIC,
)


class TestFunction(unittest.TestCase):
    def test_get_name(self):
        function = Function(
            name=A_FUNCTION_NAME,
            start_address=ANY_ADDRESS,
            instructions=AN_INSTRUCTION_LIST,
        )

        self.assertEqual(function.name, A_FUNCTION_NAME)

    def test_identify_basic_blocks(self):
        function = Function(
            name=A_FUNCTION_NAME,
            start_address=ANY_ADDRESS,
            instructions=AN_INSTRUCTION_LIST,
        )

        function.identify_basic_blocks()

        self.assertEqual(len(function.basic_blocks), 2)
        self.assertEqual(function.basic_blocks[0].start_address, Address(0x1000))
        self.assertEqual(function.basic_blocks[1].start_address, Address(0x1002))

    def test_identify_successors_and_predecessors(self):
        an_instruction_list_with_multiple_blocks = AN_INSTRUCTION_LIST + [
            Instruction(address=Address(0x1004), mnemonic="je", op_str="0x1000"),
            Instruction(
                address=Address(0x1005), mnemonic=RETURN_MNEMONIC, op_str=ANY_OP_STR
            ),
            Instruction(address=Address(0x1006), mnemonic="je", op_str="0x1009"),
            Instruction(
                address=Address(0x1007), mnemonic=ANY_MNEMONIC, op_str=ANY_OP_STR
            ),
            Instruction(
                address=Address(0x1008), mnemonic=RETURN_MNEMONIC, op_str=ANY_OP_STR
            ),
            Instruction(
                address=Address(0x1009), mnemonic=RETURN_MNEMONIC, op_str=ANY_OP_STR
            ),
        ]
        function = Function(
            name=A_FUNCTION_NAME,
            start_address=ANY_ADDRESS,
            instructions=an_instruction_list_with_multiple_blocks,
        )

        function.identify_basic_blocks()
        function.identify_successors_and_predecessors()

        self.assertEqual(len(function.basic_blocks), 7)
        self.assertEqual(function.basic_blocks[0].start_address, Address(0x1000))
        self.assertEqual(function.basic_blocks[1].start_address, Address(0x1002))
        self.assertEqual(function.basic_blocks[2].start_address, Address(0x1004))
        self.assertEqual(function.basic_blocks[3].start_address, Address(0x1005))
        self.assertEqual(function.basic_blocks[4].start_address, Address(0x1006))
        self.assertEqual(function.basic_blocks[5].start_address, Address(0x1007))
        self.assertEqual(function.basic_blocks[6].start_address, Address(0x1009))

        self.assertFalse(function.basic_blocks[0].successors)
        self.assertFalse(function.basic_blocks[1].successors)
        self.assertIn(function.basic_blocks[0], function.basic_blocks[2].successors)
        self.assertIn(function.basic_blocks[3], function.basic_blocks[2].successors)
        self.assertFalse(function.basic_blocks[3].successors)
        self.assertIn(function.basic_blocks[5], function.basic_blocks[4].successors)
        self.assertIn(function.basic_blocks[6], function.basic_blocks[4].successors)
        self.assertFalse(function.basic_blocks[5].successors)
        self.assertFalse(function.basic_blocks[6].successors)

        self.assertIn(function.basic_blocks[2], function.basic_blocks[0].predecessors)
        self.assertFalse(function.basic_blocks[1].predecessors)
        self.assertFalse(function.basic_blocks[2].predecessors)
        self.assertIn(function.basic_blocks[2], function.basic_blocks[3].predecessors)
        self.assertFalse(function.basic_blocks[4].predecessors)
        self.assertIn(function.basic_blocks[4], function.basic_blocks[5].predecessors)
        self.assertIn(function.basic_blocks[4], function.basic_blocks[6].predecessors)
