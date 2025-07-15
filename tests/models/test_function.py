import unittest

from src.models import Function, Address
from tests.fixtures import (
    ANY_ADDRESS,
    A_FUNCTION_NAME,
    AN_INSTRUCTION_LIST,
)


class TestIdentifyBasicBlocks(unittest.TestCase):
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
