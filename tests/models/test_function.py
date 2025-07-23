import unittest
from unittest.mock import patch

from src.models.function import Function
from tests.fixtures import (
    ANY_ADDRESS,
    A_FUNCTION_NAME,
    AN_INSTRUCTION_LIST,
)


class TestFunction(unittest.TestCase):
    def setUp(self):
        self.a_function = Function(
            name=A_FUNCTION_NAME,
            start_address=ANY_ADDRESS,
            instructions=AN_INSTRUCTION_LIST,
        )

    def test_get_name(self):
        self.assertEqual(self.a_function.name, A_FUNCTION_NAME)

    def test_get_start_address(self):
        self.assertEqual(self.a_function.start_address, ANY_ADDRESS)

    def test_get_instructions(self):
        self.assertEqual(self.a_function.instructions, AN_INSTRUCTION_LIST)

    def test_get_basic_blocks(self):
        self.assertEqual(self.a_function.basic_blocks, [])

    @patch("src.models.function.identify_basic_blocks")
    def test_analyze(self, identify_basic_blocks_mock):
        self.a_function.analyze()

        identify_basic_blocks_mock.assert_called_once()
