import unittest
from unittest.mock import mock_open, patch, MagicMock

from src.models import Instruction, BasicBlock
from src.output import write_instructions_to_file, export_all_control_flow_graphs
from tests.fixtures import ANY_ADDRESS, A_FUNCTION_NAME, AN_INSTRUCTION_LIST


class TestOutput(unittest.TestCase):
    @patch("os.makedirs")
    @patch("builtins.open", new_callable=mock_open)
    def test_write_instructions_to_file(self, mock_file, mock_makedirs):
        any_executable_name = "executable"
        an_instruction_without_a_translation = Instruction(
            address=ANY_ADDRESS, mnemonic="mov", op_str="eax, ebx"
        )
        an_instruction_with_a_translation = Instruction(
            address=ANY_ADDRESS, mnemonic="add", op_str="eax, 1"
        )
        an_instruction_with_a_translation.translation = "Add 1 to EAX"

        instructions = {
            ".text": [
                an_instruction_without_a_translation,
                an_instruction_with_a_translation,
            ],
            ".other_section": [an_instruction_without_a_translation],
        }

        write_instructions_to_file(any_executable_name, instructions)

        mock_file.assert_called_once_with(
            f"output/{any_executable_name}.asm", "w", encoding="utf-8"
        )

        handle = mock_file()
        handle.write.assert_any_call(
            f"{ANY_ADDRESS.to_hex_string()}:\t"
            f"{an_instruction_without_a_translation.mnemonic}\t"
            f"{an_instruction_without_a_translation.op_str}\t\n"
        )
        handle.write.assert_any_call(
            f"{ANY_ADDRESS.to_hex_string()}:\t"
            f"{an_instruction_with_a_translation.mnemonic}\t"
            f"{an_instruction_with_a_translation.op_str}\t"
            f"; {an_instruction_with_a_translation.translation}\n"
        )

    @patch("src.output.Digraph")
    @patch("os.makedirs")
    def test_export_all_control_flow_graphs(self, mock_makedirs, mock_digraph):
        a_basic_block = BasicBlock(
            start_address=ANY_ADDRESS, instructions=AN_INSTRUCTION_LIST
        )
        another_basic_block = BasicBlock(start_address=ANY_ADDRESS, instructions=[])
        a_basic_block.add_successor(another_basic_block)

        a_function = MagicMock()
        a_function.name = A_FUNCTION_NAME
        a_function.basic_blocks = [a_basic_block, another_basic_block]
        functions = {A_FUNCTION_NAME: a_function}
        an_executable_name = "file"

        mock_dot = MagicMock()
        mock_digraph.return_value = mock_dot

        export_all_control_flow_graphs(an_executable_name, functions)

        mock_makedirs.assert_called()
        mock_digraph.assert_called()
        mock_dot.render.assert_called()
        args, _ = mock_dot.render.call_args

        self.assertIn(f"output/{an_executable_name}/{A_FUNCTION_NAME}", args[0])
