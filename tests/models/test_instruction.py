import unittest

from src.models import Instruction
from tests.fixtures import ANY_ADDRESS, ANY_MNEMONIC, ANY_OP_STR, ANY_OBJECT


class TestInstruction(unittest.TestCase):
    def setUp(self):
        self.an_instruction = Instruction(
            address=ANY_ADDRESS, mnemonic=ANY_MNEMONIC, op_str=ANY_OP_STR
        )

    def test_equal_instructions_are_equal(self):
        another_instruction = Instruction(
            address=ANY_ADDRESS, mnemonic=ANY_MNEMONIC, op_str=ANY_OP_STR
        )

        self.assertEqual(self.an_instruction, another_instruction)

    def test_different_instructions_are_not_equal(self):
        another_instruction = Instruction(
            address=ANY_ADDRESS, mnemonic="any", op_str=ANY_OP_STR
        )

        self.assertNotEqual(self.an_instruction, another_instruction)

    def test_different_objects_are_not_equal(self):
        self.assertNotEqual(self.an_instruction, ANY_OBJECT)

    def test_setting_translation(self):
        a_translation = "some string"

        self.an_instruction.translation = a_translation

        self.assertEqual(self.an_instruction.translation, a_translation)
