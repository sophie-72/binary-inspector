from src.constants import JUMP_MNEMONIC, RETURN_MNEMONIC, TEXT_SECTION_NAME
from src.models.address import Address
from src.models.instruction import Instruction

ANY_ADDRESS = Address(0x4)
ANY_OTHER_ADDRESS = Address(0x5)
ANY_MNEMONIC = "mov"
ANY_OP_STR = ""
ANY_NUMBER = 1
A_FUNCTION_NAME = "function"
A_STRING = "Hello, World!"
AN_INSTRUCTION_LIST = [
    Instruction(address=Address(0x1000), mnemonic=ANY_MNEMONIC, op_str=ANY_OP_STR),
    Instruction(
        address=Address(0x1001),
        mnemonic=JUMP_MNEMONIC,
        op_str=ANY_ADDRESS.to_hex_string(),
    ),
    Instruction(address=Address(0x1002), mnemonic=ANY_MNEMONIC, op_str=ANY_OP_STR),
    Instruction(address=Address(0x1003), mnemonic=RETURN_MNEMONIC, op_str=ANY_OP_STR),
]
ANY_OBJECT = "an object"
A_SECTION_NAME = TEXT_SECTION_NAME
