"""Types used by multiple modules"""

from typing import Dict, List

from src.models.address import Address
from src.models.instruction import Instruction
from src.models.basic_block import BasicBlock
from src.models.function import Function

InstructionList = List[Instruction]
BasicBlockList = List[BasicBlock]
SectionNameToInstructionsMapping = Dict[str, InstructionList]
FunctionNameToFunctionMapping = Dict[str, Function]
AddressToStringMapping = Dict[Address, str]
