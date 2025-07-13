"""Types used by multiple modules"""

from typing import Dict, List

from src.models import Instruction, Address, BasicBlock

InstructionList = List[Instruction]
BasicBlockList = List[BasicBlock]
SectionNameToInstructionsMapping = Dict[str, InstructionList]
AddressToStringMapping = Dict[Address, str]
