import unittest

from src.functions import identify_functions
from src.models import Instruction, Address, Function, BasicBlock
from tests.fixtures import ANY_MNEMONIC, ANY_OP_STR, A_FUNCTION_NAME


class TestIdentifyFunctions(unittest.TestCase):
    def test_identify_functions(self):
        any_section_name = ".text"
        another_function_name = "other"
        return_mnemonic = "ret"
        instructions = [
            Instruction(
                address=Address(0x1000), mnemonic=ANY_MNEMONIC, op_str=ANY_OP_STR
            ),
            Instruction(
                address=Address(0x1001), mnemonic=return_mnemonic, op_str=ANY_OP_STR
            ),
            Instruction(
                address=Address(0x1002), mnemonic=ANY_MNEMONIC, op_str=ANY_OP_STR
            ),
            Instruction(
                address=Address(0x1003), mnemonic=return_mnemonic, op_str=ANY_OP_STR
            ),
        ]
        function_symbols = {
            Address(0x1002): another_function_name,
            Address(0x1000): A_FUNCTION_NAME,
        }

        expected_first_function_instructions = [instructions[0], instructions[1]]
        expected_first_function = Function(
            name=A_FUNCTION_NAME,
            start_address=Address(0x1000),
            instructions=expected_first_function_instructions,
        )
        expected_first_function.basic_blocks = [
            BasicBlock(
                start_address=Address(0x1000),
                instructions=expected_first_function_instructions,
            )
        ]
        expected_second_function_instructions = [instructions[2], instructions[3]]
        expected_second_function = Function(
            name=another_function_name,
            start_address=Address(0x1002),
            instructions=expected_second_function_instructions,
        )
        expected_second_function.basic_blocks = [
            BasicBlock(
                start_address=Address(0x1002),
                instructions=expected_second_function_instructions,
            )
        ]
        expected_functions = {
            A_FUNCTION_NAME: expected_first_function,
            another_function_name: expected_second_function,
        }

        result = identify_functions({any_section_name: instructions}, function_symbols)
        self.assertEqual(result, expected_functions)
