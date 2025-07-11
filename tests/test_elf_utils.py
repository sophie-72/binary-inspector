import unittest
from unittest.mock import patch, MagicMock

from src.elf_utils import (
    get_file_instructions,
    get_file_relocations,
    get_file_strings,
    get_function_symbols,
)
from src.models import Instruction
from tests.fixtures import ANY_ADDRESS, ANY_NUMBER, A_FUNCTION_NAME, A_STRING

ANY_FILENAME = "filename"


class TestElfUtils(unittest.TestCase):
    def setUp(self):
        patcher = patch("src.elf_utils._open_elf_file")
        mock_open_elf_file = patcher.start()
        self.addCleanup(patcher.stop)

        self.mock_elf_file = MagicMock()
        mock_open_elf_file.return_value = self.mock_elf_file

    def test_get_file_instructions(self):
        a_section_name = ".text"
        some_opcodes = b"\x55\x48\x89\xe5"
        instructions_matching_opcodes = [
            Instruction(address=ANY_ADDRESS, mnemonic="push", op_str="rbp"),
            Instruction(address=ANY_ADDRESS + 1, mnemonic="mov", op_str="rbp, rsp"),
        ]

        mock_section = MagicMock()
        mock_section.name = a_section_name
        mock_section.__getitem__.side_effect = lambda key: {
            "sh_type": "SHT_PROGBITS",
            "sh_addr": ANY_ADDRESS,
        }[key]
        mock_section.data.return_value = some_opcodes
        self.mock_elf_file.iter_sections.return_value = [mock_section]

        expected_instructions = {a_section_name: instructions_matching_opcodes}

        result = get_file_instructions(ANY_FILENAME)
        self.assertEqual(result, expected_instructions)

    def test_get_file_relocations(self):
        mock_relocation = MagicMock()
        mock_relocation.__getitem__.side_effect = lambda key: {
            "r_info_sym": ANY_NUMBER,
            "r_offset": ANY_ADDRESS,
        }[key]
        mock_rela_dyn = MagicMock()
        mock_rela_dyn.__getitem__.side_effect = lambda key: {"sh_link": ANY_NUMBER}[key]
        mock_rela_dyn.iter_relocations.return_value = [mock_relocation]
        mock_symbol = MagicMock()
        mock_symbol.name = A_FUNCTION_NAME
        mock_symbol_table = MagicMock()
        mock_symbol_table.get_symbol.return_value = mock_symbol
        self.mock_elf_file.get_section_by_name.return_value = mock_rela_dyn
        self.mock_elf_file.get_section.return_value = mock_symbol_table

        expected_relocations = {
            f"{hex(ANY_ADDRESS)}": A_FUNCTION_NAME,
        }

        result = get_file_relocations(ANY_FILENAME)
        self.assertEqual(result, expected_relocations)

    def test_get_file_strings(self):
        mock_rodata_section = MagicMock()
        mock_rodata_section.data.return_value = A_STRING.encode("utf-8")
        mock_rodata_section.__getitem__.side_effect = lambda key: {
            "sh_addr": ANY_ADDRESS,
        }[key]
        self.mock_elf_file.get_section_by_name.return_value = mock_rodata_section

        expected_strings = {
            f"{hex(ANY_ADDRESS)}": A_STRING,
        }

        result = get_file_strings(ANY_FILENAME)
        self.assertEqual(result, expected_strings)

    def test_get_function_symbols(self):
        mock_symbol = MagicMock()
        mock_symbol.__getitem__.side_effect = lambda key: {
            "st_info": {"type": "STT_FUNC"},
            "st_value": ANY_ADDRESS,
        }[key]
        mock_symbol.name = A_FUNCTION_NAME
        mock_symtab = MagicMock()
        mock_symtab.iter_symbols.return_value = [mock_symbol]
        self.mock_elf_file.get_section_by_name.side_effect = [mock_symtab, None]

        expected_functions = {
            ANY_ADDRESS: A_FUNCTION_NAME,
        }

        result = get_function_symbols(ANY_FILENAME)
        self.assertEqual(result, expected_functions)
