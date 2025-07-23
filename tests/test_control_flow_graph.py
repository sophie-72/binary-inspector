import unittest

from src.constants import RETURN_MNEMONIC
from src.control_flow_graph import (
    identify_basic_blocks,
    identify_successors_and_predecessors,
)
from src.models import Address, Instruction
from tests.fixtures import (
    AN_INSTRUCTION_LIST,
    ANY_OP_STR,
    ANY_MNEMONIC,
)


class TestControlFlowGraph(unittest.TestCase):
    def test_identify_basic_blocks(self):
        result = identify_basic_blocks(AN_INSTRUCTION_LIST)

        self.assertEqual(len(result), 2)
        self.assertEqual(result[0].start_address, Address(0x1000))
        self.assertEqual(result[1].start_address, Address(0x1002))

    def test_identify_successors_and_predecessors(self):
        an_instruction_list_with_multiple_blocks = AN_INSTRUCTION_LIST + [
            Instruction(address=Address(0x1004), mnemonic="je", op_str="0x1000"),
            Instruction(
                address=Address(0x1005), mnemonic=RETURN_MNEMONIC, op_str=ANY_OP_STR
            ),
            Instruction(address=Address(0x1006), mnemonic="je", op_str="0x1010"),
            Instruction(
                address=Address(0x1007), mnemonic=ANY_MNEMONIC, op_str=ANY_OP_STR
            ),
            Instruction(address=Address(0x1008), mnemonic="jmp", op_str="rax"),
            Instruction(
                address=Address(0x1009), mnemonic=RETURN_MNEMONIC, op_str=ANY_OP_STR
            ),
            Instruction(address=Address(0x1010), mnemonic="leave", op_str=ANY_OP_STR),
            Instruction(
                address=Address(0x1011), mnemonic=RETURN_MNEMONIC, op_str=ANY_OP_STR
            ),
        ]

        basic_blocks = identify_basic_blocks(an_instruction_list_with_multiple_blocks)
        identify_successors_and_predecessors(basic_blocks)

        self.assertEqual(len(basic_blocks), 9)
        self.assertEqual(basic_blocks[0].start_address, Address(0x1000))
        self.assertEqual(basic_blocks[1].start_address, Address(0x1002))
        self.assertEqual(basic_blocks[2].start_address, Address(0x1004))
        self.assertEqual(basic_blocks[3].start_address, Address(0x1005))
        self.assertEqual(basic_blocks[4].start_address, Address(0x1006))
        self.assertEqual(basic_blocks[5].start_address, Address(0x1007))
        self.assertEqual(basic_blocks[6].start_address, Address(0x1009))
        self.assertEqual(basic_blocks[7].start_address, Address(0x1010))
        self.assertEqual(basic_blocks[8].start_address, Address(0x1011))

        self.assertFalse(basic_blocks[0].successors)
        self.assertFalse(basic_blocks[1].successors)
        self.assertIn(basic_blocks[0], basic_blocks[2].successors)
        self.assertIn(basic_blocks[3], basic_blocks[2].successors)
        self.assertFalse(basic_blocks[3].successors)
        self.assertIn(basic_blocks[5], basic_blocks[4].successors)
        self.assertIn(basic_blocks[7], basic_blocks[4].successors)
        self.assertFalse(basic_blocks[5].successors)
        self.assertFalse(basic_blocks[6].successors)
        self.assertIn(basic_blocks[8], basic_blocks[7].successors)
        self.assertFalse(basic_blocks[8].successors)

        self.assertIn(basic_blocks[2], basic_blocks[0].predecessors)
        self.assertFalse(basic_blocks[1].predecessors)
        self.assertFalse(basic_blocks[2].predecessors)
        self.assertIn(basic_blocks[2], basic_blocks[3].predecessors)
        self.assertFalse(basic_blocks[4].predecessors)
        self.assertIn(basic_blocks[4], basic_blocks[5].predecessors)
        self.assertFalse(basic_blocks[6].predecessors)
        self.assertIn(basic_blocks[4], basic_blocks[7].predecessors)
        self.assertIn(basic_blocks[7], basic_blocks[8].predecessors)
