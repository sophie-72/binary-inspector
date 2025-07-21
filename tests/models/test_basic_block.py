import unittest

from src.models import BasicBlock
from tests.fixtures import ANY_ADDRESS, AN_INSTRUCTION_LIST


class TestBasicBlock(unittest.TestCase):
    def test_equal_same_values(self):
        first_basic_block = BasicBlock(ANY_ADDRESS, AN_INSTRUCTION_LIST)
        second_basic_block = BasicBlock(ANY_ADDRESS, AN_INSTRUCTION_LIST)

        self.assertEqual(first_basic_block, second_basic_block)

    def test_equal_different_values(self):
        first_basic_block = BasicBlock(ANY_ADDRESS, AN_INSTRUCTION_LIST)
        second_basic_block = BasicBlock(ANY_ADDRESS, [])

        self.assertNotEqual(first_basic_block, second_basic_block)

    def test_equal_different_objects(self):
        first_basic_block = BasicBlock(ANY_ADDRESS, AN_INSTRUCTION_LIST)
        second_basic_block = "not a basic block"

        self.assertNotEqual(first_basic_block, second_basic_block)
