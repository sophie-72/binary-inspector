import unittest

from src.models import Instruction
from tests.fixtures import ANY_ADDRESS, ANY_MNEMONIC, ANY_OP_STR


class TestInstruction(unittest.TestCase):
    def test_equal_same_value(self):
        first_address = Instruction(
            address=ANY_ADDRESS, mnemonic=ANY_MNEMONIC, op_str=ANY_OP_STR
        )
        second_address = Instruction(
            address=ANY_ADDRESS, mnemonic=ANY_MNEMONIC, op_str=ANY_OP_STR
        )

        self.assertEqual(first_address, second_address)

    def test_equal_different_value(self):
        first_address = Instruction(
            address=ANY_ADDRESS, mnemonic=ANY_MNEMONIC, op_str=ANY_OP_STR
        )
        second_address = Instruction(
            address=ANY_ADDRESS, mnemonic="any", op_str=ANY_OP_STR
        )

        self.assertNotEqual(first_address, second_address)

    def test_equal_different_objects(self):
        first_address = Instruction(
            address=ANY_ADDRESS, mnemonic=ANY_MNEMONIC, op_str=ANY_OP_STR
        )
        second_address = "not an address"

        self.assertNotEqual(first_address, second_address)
