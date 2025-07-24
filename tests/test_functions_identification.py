import unittest

from src.functions_identification import identify_functions
from src.models import Address
from src.models.function import Function
from tests.fixtures import (
    A_FUNCTION_NAME,
    AN_INSTRUCTION_LIST,
    A_SECTION_NAME,
)

ANOTHER_FUNCTION_NAME = "other"


class TestFunctionsIdentification(unittest.TestCase):
    def test_identify_functions(self):
        function_symbols = {
            Address(0x1002): ANOTHER_FUNCTION_NAME,
            Address(0x1000): A_FUNCTION_NAME,
        }

        result = identify_functions(
            instructions={A_SECTION_NAME: AN_INSTRUCTION_LIST},
            function_symbols=function_symbols,
        )

        expected_first_function_instructions = [
            AN_INSTRUCTION_LIST[0],
            AN_INSTRUCTION_LIST[1],
        ]
        expected_first_function = Function(
            name=A_FUNCTION_NAME,
            start_address=Address(0x1000),
            instructions=expected_first_function_instructions,
        )
        expected_second_function_instructions = [
            AN_INSTRUCTION_LIST[2],
            AN_INSTRUCTION_LIST[3],
        ]
        expected_second_function = Function(
            name=ANOTHER_FUNCTION_NAME,
            start_address=Address(0x1002),
            instructions=expected_second_function_instructions,
        )

        self.assertEqual(len(result), 2)
        self.assertIn(A_FUNCTION_NAME, result.keys())
        self.assertIn(ANOTHER_FUNCTION_NAME, result.keys())

        result_first_function = result[A_FUNCTION_NAME]
        result_second_function = result[ANOTHER_FUNCTION_NAME]

        self.assertEqual(
            result_first_function.start_address, expected_first_function.start_address
        )
        self.assertEqual(
            result_second_function.start_address, expected_second_function.start_address
        )
        self.assertEqual(
            result_first_function.instructions, expected_first_function.instructions
        )
        self.assertEqual(
            result_second_function.instructions, expected_second_function.instructions
        )
