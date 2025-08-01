import unittest

from src.models.address import Address
from src.models.instruction import Instruction
from src.translation import translate_instructions
from tests.fixtures import (
    ANY_ADDRESS,
    ANY_MNEMONIC,
    ANY_OP_STR,
    A_FUNCTION_NAME,
    A_STRING,
)

ANY_SECTION_NAME = ".section"
ANOTHER_FUNCTION_NAME = "another"
CALL_MNEMONIC = "call"
A_FUNCTION_ADDRESS = Address(0x10)
ANOTHER_FUNCTION_ADDRESS = Address(0x20)
A_STRING_ADDRESS = Address(0x30)


class TestTranslateInstructions(unittest.TestCase):
    def setUp(self):
        self.relocations = {A_FUNCTION_ADDRESS: A_FUNCTION_NAME}
        self.function_symbols = {ANOTHER_FUNCTION_ADDRESS: ANOTHER_FUNCTION_NAME}
        self.strings = {A_STRING_ADDRESS: A_STRING}

    def test_instruction_with_pointer(self):
        a_pointer_address = 0x1
        pointer_types = ["qword", "byte"]

        for pointer_type in pointer_types:
            with self.subTest(pointer_type=pointer_type):
                op_str_with_pointer = f"{pointer_type} ptr [{a_pointer_address}]"
                an_instruction_with_pointer = Instruction(
                    address=ANY_ADDRESS,
                    mnemonic=ANY_MNEMONIC,
                    op_str=op_str_with_pointer,
                )
                instructions = {ANY_SECTION_NAME: [an_instruction_with_pointer]}

                translate_instructions(
                    instructions, self.relocations, self.function_symbols, self.strings
                )

                expected_instruction_with_pointer_translation = (
                    f"{ANY_MNEMONIC} memory[{a_pointer_address}]"
                )
                self.assertEqual(
                    instructions[ANY_SECTION_NAME][0].translation,
                    expected_instruction_with_pointer_translation,
                )

    def test_instruction_with_rip(self):
        op_str_with_rip = "rip"
        an_instruction_with_rip = Instruction(
            address=ANY_ADDRESS, mnemonic=ANY_MNEMONIC, op_str=op_str_with_rip
        )
        another_instruction_address = Address(ANY_ADDRESS.value + 1)
        another_instruction = Instruction(
            address=another_instruction_address,
            mnemonic=ANY_MNEMONIC,
            op_str=ANY_OP_STR,
        )
        instructions = {
            ANY_SECTION_NAME: [an_instruction_with_rip, another_instruction]
        }

        translate_instructions(
            instructions, self.relocations, self.function_symbols, self.strings
        )

        expected_instruction_with_rip_translation = (
            f"{ANY_MNEMONIC} {another_instruction_address.to_hex_string()}"
        )
        expected_other_instruction_translation = None
        self.assertEqual(
            instructions[ANY_SECTION_NAME][0].translation,
            expected_instruction_with_rip_translation,
        )
        self.assertEqual(
            instructions[ANY_SECTION_NAME][1].translation,
            expected_other_instruction_translation,
        )

    def test_instruction_with_addition(self):
        any_other_address = Address(ANY_ADDRESS.value + 1)
        op_str_with_addition = (
            f"{ANY_ADDRESS.to_hex_string()} + {any_other_address.to_hex_string()}"
        )
        an_instruction_with_addition = Instruction(
            address=ANY_ADDRESS, mnemonic=ANY_MNEMONIC, op_str=op_str_with_addition
        )
        instructions = {ANY_SECTION_NAME: [an_instruction_with_addition]}

        translate_instructions(
            instructions, self.relocations, self.function_symbols, self.strings
        )

        expected_op_str = Address(
            ANY_ADDRESS.value + any_other_address.value
        ).to_hex_string()
        expected_instruction_with_addition_translation = (
            f"{ANY_MNEMONIC} {expected_op_str}"
        )
        self.assertEqual(
            instructions[ANY_SECTION_NAME][0].translation,
            expected_instruction_with_addition_translation,
        )

    def test_instruction_with_function_address(self):
        op_str_with_function_address = f"memory[{A_FUNCTION_ADDRESS.to_hex_string()}]"
        an_instruction_with_function_address = Instruction(
            address=ANY_ADDRESS,
            mnemonic=ANY_MNEMONIC,
            op_str=op_str_with_function_address,
        )
        instructions = {ANY_SECTION_NAME: [an_instruction_with_function_address]}

        translate_instructions(
            instructions, self.relocations, self.function_symbols, self.strings
        )

        expected_instruction_with_function_address_translation = (
            f"{ANY_MNEMONIC} {A_FUNCTION_NAME}"
        )
        self.assertEqual(
            instructions[ANY_SECTION_NAME][0].translation,
            expected_instruction_with_function_address_translation,
        )

    def test_instruction_with_function_call(self):
        op_str_with_function_address = ANOTHER_FUNCTION_ADDRESS.to_hex_string()
        an_instruction_with_function_call = Instruction(
            address=ANY_ADDRESS,
            mnemonic=CALL_MNEMONIC,
            op_str=op_str_with_function_address,
        )
        instructions = {ANY_SECTION_NAME: [an_instruction_with_function_call]}

        translate_instructions(
            instructions, self.relocations, self.function_symbols, self.strings
        )

        expected_instruction_with_function_call_translation = (
            f"{CALL_MNEMONIC} {ANOTHER_FUNCTION_NAME}"
        )
        self.assertEqual(
            instructions[ANY_SECTION_NAME][0].translation,
            expected_instruction_with_function_call_translation,
        )

    def test_instruction_with_string_address(self):
        op_str_with_string_address = A_STRING_ADDRESS.to_hex_string()
        an_instruction_with_string_address = Instruction(
            address=ANY_ADDRESS,
            mnemonic=ANY_MNEMONIC,
            op_str=op_str_with_string_address,
        )
        instructions = {ANY_SECTION_NAME: [an_instruction_with_string_address]}

        translate_instructions(
            instructions, self.relocations, self.function_symbols, self.strings
        )

        expected_instruction_with_string_address_translation = (
            f'{ANY_MNEMONIC} "{A_STRING}"'
        )
        self.assertEqual(
            instructions[ANY_SECTION_NAME][0].translation,
            expected_instruction_with_string_address_translation,
        )
