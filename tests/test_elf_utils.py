import unittest
from unittest.mock import patch, MagicMock

from src.elf_utils import get_file_instructions
from src.models import Instruction


class TestGetFileInstructions(unittest.TestCase):
    @patch("src.elf_utils._open_elf_file")
    def test_given_filename_with_opcodes_when_getting_file_instructions_then_return_instructions(
        self, mock_open_elf_file
    ):
        mock_elf_file = MagicMock()
        mock_section = MagicMock()
        mock_section.name = ".text"
        mock_section.__getitem__.side_effect = lambda key: {
            "sh_type": "SHT_PROGBITS",
            "sh_addr": 0x0,
        }[key]
        mock_section.data.return_value = b"\x55\x48\x89\xe5"
        mock_elf_file.iter_sections.return_value = [mock_section]
        mock_open_elf_file.return_value = mock_elf_file

        expected_instructions = {
            ".text": [
                Instruction(address=0x0, mnemonic="push", op_str="rbp"),
                Instruction(address=0x1, mnemonic="mov", op_str="rbp, rsp"),
            ]
        }

        result = get_file_instructions("dummy.elf")
        self.assertEqual(result, expected_instructions)
