import unittest
from unittest.mock import mock_open, patch

from src.models import Instruction
from src.output import write_to_file
from tests.fixtures import ANY_ADDRESS


class TestWriteToFile(unittest.TestCase):
    @patch("builtins.open", new_callable=mock_open)
    def test_write_to_file(self, mock_file):
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

        write_to_file(any_executable_name, instructions)

        mock_file.assert_called_once_with(
            f"{any_executable_name}.asm", "w", encoding="utf-8"
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
