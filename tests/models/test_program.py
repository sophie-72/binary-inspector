import unittest
from unittest.mock import patch, MagicMock, mock_open

from src.models.address import Address
from src.models.program import Program, FileContent
from tests.fixtures import (
    A_FUNCTION_NAME,
    AN_INSTRUCTION_LIST,
    ANY_ADDRESS,
    A_STRING,
    A_SECTION_NAME,
)

ANOTHER_FUNCTION_NAME = "other"


class TestProgram(unittest.TestCase):
    def setUp(self):
        function_symbols = {
            Address(0x1002): ANOTHER_FUNCTION_NAME,
            Address(0x1000): A_FUNCTION_NAME,
        }

        file_content = FileContent(
            instructions={A_SECTION_NAME: AN_INSTRUCTION_LIST},
            function_symbols=function_symbols,
        )
        self.program = Program(file_content=file_content)

    def test_no_executable_name_no_file_content_when_creating_a_program_then_raise_runtime_error(
        self,
    ):
        with self.assertRaises(RuntimeError):
            Program()

    @patch("src.models.program.ELFProcessor")
    @patch("src.models.program.ELFFile")
    @patch("builtins.open", new_callable=mock_open, read_data=b"ELF")
    def test_init_with_executable_name(
        self, mock_file, mock_elf_file, mock_elf_processor
    ):
        a_file_name = "file"
        some_instructions = {"section": []}
        some_relocations = {ANY_ADDRESS: A_FUNCTION_NAME}
        some_strings = {ANY_ADDRESS: A_STRING}
        some_function_names = {ANY_ADDRESS: A_FUNCTION_NAME}

        mock_processor_instance = MagicMock()
        mock_processor_instance.get_file_instructions.return_value = some_instructions
        mock_processor_instance.get_file_relocations.return_value = some_relocations
        mock_processor_instance.get_file_strings.return_value = some_strings
        mock_processor_instance.get_function_names.return_value = some_function_names
        mock_elf_processor.return_value = mock_processor_instance

        program = Program(executable_name=a_file_name)

        mock_file.assert_called_once_with(a_file_name, "rb")
        mock_elf_file.assert_called_once()
        mock_elf_processor.assert_called_once_with(mock_elf_file.return_value)

        self.assertEqual(program.instructions, some_instructions)
        self.assertEqual(program.relocations, some_relocations)
        self.assertEqual(program.strings, some_strings)
        self.assertEqual(program.function_symbols, some_function_names)

    @patch("src.models.program.translate_instructions")
    def test_when_analyzing_should_call_translate_instructions(
        self, translate_instructions_mock
    ):
        self.program.analyze()

        translate_instructions_mock.assert_called_once()

    @patch("src.models.program.identify_functions")
    def test_when_analyzing_should_call_identify_functions(
        self, identify_functions_mock
    ):
        self.program.analyze()

        identify_functions_mock.assert_called_once()

    @patch("src.models.program.export_all_control_flow_graphs")
    @patch("src.models.program.write_instructions_to_file")
    def test_when_exporting_analysis_should_call_write_instructions_to_file_and_export_all_control_flow_graphs(  # pylint: disable=line-too-long
        self, write_instructions_to_file_mock, export_all_control_flow_graphs_mock
    ):
        self.program.export_analysis()

        write_instructions_to_file_mock.assert_called_once()
        export_all_control_flow_graphs_mock.assert_called_once()
