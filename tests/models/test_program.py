import unittest

from src.models import Address, Function, BasicBlock
from src.models.program import Program
from tests.fixtures import (
    A_FUNCTION_NAME,
    AN_INSTRUCTION_LIST,
)


class TestIdentifyFunctions(unittest.TestCase):
    def test_identify_functions(self):
        any_section_name = ".text"
        another_function_name = "other"
        function_symbols = {
            Address(0x1002): another_function_name,
            Address(0x1000): A_FUNCTION_NAME,
        }

        expected_first_function_instructions = [
            AN_INSTRUCTION_LIST[0],
            AN_INSTRUCTION_LIST[1],
        ]
        expected_first_function = Function(
            name=A_FUNCTION_NAME,
            start_address=Address(0x1000),
            instructions=expected_first_function_instructions,
        )
        expected_first_function.basic_blocks = [
            BasicBlock(
                start_address=Address(0x1000),
                instructions=expected_first_function_instructions,
            )
        ]
        expected_second_function_instructions = [
            AN_INSTRUCTION_LIST[2],
            AN_INSTRUCTION_LIST[3],
        ]
        expected_second_function = Function(
            name=another_function_name,
            start_address=Address(0x1002),
            instructions=expected_second_function_instructions,
        )
        expected_second_function.basic_blocks = [
            BasicBlock(
                start_address=Address(0x1002),
                instructions=expected_second_function_instructions,
            )
        ]
        expected_functions = {
            A_FUNCTION_NAME: expected_first_function,
            another_function_name: expected_second_function,
        }

        file_content = {
            "instructions": {any_section_name: AN_INSTRUCTION_LIST},
            "function_symbols": function_symbols,
        }
        program = Program(file_content=file_content)

        result = program.identify_functions()
        self.assertEqual(result, expected_functions)
