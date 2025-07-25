import unittest

from src.models.basic_block import BasicBlock
from tests.fixtures import (
    ANY_ADDRESS,
    AN_INSTRUCTION_LIST,
    ANY_OBJECT,
    ANY_OTHER_ADDRESS,
)


class TestBasicBlock(unittest.TestCase):
    def setUp(self):
        self.a_basic_block = BasicBlock(ANY_ADDRESS, AN_INSTRUCTION_LIST)

    def test_equal_basic_blocks_are_equal(self):
        another_basic_block = BasicBlock(ANY_ADDRESS, AN_INSTRUCTION_LIST)

        self.assertEqual(self.a_basic_block, another_basic_block)

    def test_basic_blocks_with_different_instruction_list_are_not_equal(self):
        another_basic_block = BasicBlock(ANY_ADDRESS, [])

        self.assertNotEqual(self.a_basic_block, another_basic_block)

    def test_different_objects_are_not_equal(self):
        self.assertNotEqual(self.a_basic_block, ANY_OBJECT)

    def test_adding_a_successor(self):
        another_basic_block = BasicBlock(ANY_OTHER_ADDRESS, [])

        self.a_basic_block.add_successor(another_basic_block)

        self.assertEqual(self.a_basic_block.successors, [another_basic_block])

    def test_adding_a_predecessor(self):
        another_basic_block = BasicBlock(ANY_OTHER_ADDRESS, [])

        self.a_basic_block.add_predecessor(another_basic_block)

        self.assertEqual(self.a_basic_block.predecessors, [another_basic_block])
