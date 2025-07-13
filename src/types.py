"""Types used by multiple modules"""

from typing import Dict, List

from src.models import Instruction, Address, BasicBlock, Function

InstructionList = List[Instruction]
BasicBlockList = List[BasicBlock]
SectionNameToInstructionsMapping = Dict[str, InstructionList]
FunctionNameToFunctionMapping = Dict[str, Function]
AddressToStringMapping = Dict[Address, str]
