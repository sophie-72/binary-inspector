import unittest
from unittest.mock import patch

from src.models import Address, Function
from src.models.program import Program, FileContent
from tests.fixtures import (
    A_FUNCTION_NAME,
    AN_INSTRUCTION_LIST,
)

ANOTHER_FUNCTION_NAME = "other"


class TestIdentifyFunctions(unittest.TestCase):
    def setUp(self):
        any_section_name = ".text"
        function_symbols = {
            Address(0x1002): ANOTHER_FUNCTION_NAME,
            Address(0x1000): A_FUNCTION_NAME,
        }

        file_content = FileContent(
            instructions={any_section_name: AN_INSTRUCTION_LIST},
            function_symbols=function_symbols,
        )
        self.program = Program(file_content=file_content)

    def test_no_executable_name_no_file_content_when_creating_a_program_should_raise_runtime_error(
        self,
    ):
        with self.assertRaises(RuntimeError):
            Program()

    @patch("src.models.program.write_instructions_to_file")
    def test_when_exporting_analysis_should_call_write_instructions_to_file(
        self, write_instructions_to_file_mock
    ):
        self.program.export_analysis()

        write_instructions_to_file_mock.assert_called_once()

    @patch("src.models.program.export_all_control_flow_graphs")
    def test_when_exporting_analysis_should_call_export_all_control_flow_graphs(
        self, export_all_control_flow_graphs_mock
    ):
        self.program.export_analysis()

        export_all_control_flow_graphs_mock.assert_called_once()

    def test_identify_functions(self):
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

        result = self.program.identify_functions()

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
