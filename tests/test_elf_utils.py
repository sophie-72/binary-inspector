import unittest
from unittest.mock import patch, MagicMock

from src.elf_utils import (
    get_file_instructions,
    get_file_relocations,
    get_file_strings,
    get_function_symbols,
)
from src.models import Instruction


class TestElfUtils(unittest.TestCase):
    @patch("src.elf_utils._open_elf_file")
    def test_get_file_instructions(self, mock_open_elf_file):
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

    @patch("src.elf_utils._open_elf_file")
    def test_get_file_relocations(self, mock_open_elf_file):
        mock_elf_file = MagicMock()
        mock_rela_dyn = MagicMock()
        mock_rela_dyn.__getitem__.side_effect = lambda key: {"sh_link": 0}[key]
        mock_relocation = MagicMock()
        mock_relocation.__getitem__.side_effect = lambda key: {
            "r_info_sym": 0,
            "r_offset": 0x1000,
        }[key]
        mock_rela_dyn.iter_relocations.return_value = [mock_relocation]
        mock_symbol = MagicMock()
        mock_symbol.name = "my_function"
        mock_symbol_table = MagicMock()
        mock_symbol_table.get_symbol.return_value = mock_symbol
        mock_elf_file.get_section_by_name.return_value = mock_rela_dyn
        mock_elf_file.get_section.return_value = mock_symbol_table
        mock_open_elf_file.return_value = mock_elf_file

        expected_relocations = {
            "0x1000": "my_function",
        }

        result = get_file_relocations("dummy.elf")
        self.assertEqual(result, expected_relocations)

    @patch("src.elf_utils._open_elf_file")
    def test_get_file_strings(self, mock_open_elf_file):
        mock_elf_file = MagicMock()
        mock_rodata_section = MagicMock()
        mock_rodata_section.data.return_value = b"Hello, World!"
        mock_rodata_section.__getitem__.side_effect = lambda key: {
            "sh_addr": 0x2000,
        }[key]
        mock_elf_file.get_section_by_name.return_value = mock_rodata_section
        mock_open_elf_file.return_value = mock_elf_file

        expected_strings = {
            "0x2000": "Hello, World!",
        }

        result = get_file_strings("dummy.elf")
        self.assertEqual(result, expected_strings)

    @patch("src.elf_utils._open_elf_file")
    def test_get_function_symbols(self, mock_open_elf_file):
        mock_elf_file = MagicMock()
        mock_symtab = MagicMock()
        mock_symbol = MagicMock()
        mock_symbol.__getitem__.side_effect = lambda key: {
            "st_info": {"type": "STT_FUNC"},
            "st_value": 0x3000,
        }[key]
        mock_symbol.name = "my_function"
        mock_symtab.iter_symbols.return_value = [mock_symbol]
        mock_elf_file.get_section_by_name.side_effect = [mock_symtab, None]
        mock_open_elf_file.return_value = mock_elf_file

        expected_functions = {
            0x3000: "my_function",
        }

        result = get_function_symbols("dummy.elf")
        self.assertEqual(result, expected_functions)
