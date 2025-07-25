import unittest
from unittest.mock import MagicMock

from src.constants import (
    SECTION_HEADER_ADDRESS,
    SECTION_HEADER_TYPE,
    ENCODING,
)
from src.models.address import Address
from src.models.instruction import Instruction
from src.models.elf_processor import ELFProcessor
from tests.fixtures import (
    ANY_ADDRESS,
    ANY_NUMBER,
    A_FUNCTION_NAME,
    A_STRING,
    A_SECTION_NAME,
)


class TestElfProcessor(unittest.TestCase):
    def setUp(self):
        self.mock_elf_file = MagicMock()
        self.elf_processor = ELFProcessor(self.mock_elf_file)

    def test_get_file_instructions(self):
        some_opcodes = b"\x55\x48\x89\xe5"
        instructions_matching_opcodes = [
            Instruction(address=ANY_ADDRESS, mnemonic="push", op_str="rbp"),
            Instruction(
                address=Address(ANY_ADDRESS.value + 1),
                mnemonic="mov",
                op_str="rbp, rsp",
            ),
        ]

        mock_section = MagicMock()
        mock_section.name = A_SECTION_NAME
        mock_section.__getitem__.side_effect = lambda key: {
            SECTION_HEADER_TYPE: "SHT_PROGBITS",
            SECTION_HEADER_ADDRESS: ANY_ADDRESS.value,
        }[key]
        mock_section.data.return_value = some_opcodes
        self.mock_elf_file.iter_sections.return_value = [mock_section]

        expected_instructions = {A_SECTION_NAME: instructions_matching_opcodes}

        result = self.elf_processor.get_file_instructions()
        self.assertEqual(result, expected_instructions)

    def test_get_file_relocations(self):
        mock_relocation = MagicMock()
        mock_relocation.__getitem__.side_effect = lambda key: {
            "r_info_sym": ANY_NUMBER,
            "r_offset": ANY_ADDRESS.value,
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
            ANY_ADDRESS: A_FUNCTION_NAME,
        }

        result = self.elf_processor.get_file_relocations()
        self.assertEqual(result, expected_relocations)

    def test_get_file_strings(self):
        mock_rodata_section = MagicMock()
        mock_rodata_section.data.return_value = A_STRING.encode(ENCODING)
        mock_rodata_section.__getitem__.side_effect = lambda key: {
            SECTION_HEADER_ADDRESS: ANY_ADDRESS.value,
        }[key]
        self.mock_elf_file.get_section_by_name.return_value = mock_rodata_section

        expected_strings = {
            ANY_ADDRESS: A_STRING,
        }

        result = self.elf_processor.get_file_strings()
        self.assertEqual(result, expected_strings)

    def test_get_function_names(self):
        mock_symbol = MagicMock()
        mock_symbol.__getitem__.side_effect = lambda key: {
            "st_info": {"type": "STT_FUNC"},
            "st_value": ANY_ADDRESS.value,
        }[key]
        mock_symbol.name = A_FUNCTION_NAME
        mock_symtab = MagicMock()
        mock_symtab.iter_symbols.return_value = [mock_symbol]
        self.mock_elf_file.get_section_by_name.side_effect = [mock_symtab, None]

        expected_functions = {
            ANY_ADDRESS: A_FUNCTION_NAME,
        }

        result = self.elf_processor.get_function_names()
        self.assertEqual(result, expected_functions)
