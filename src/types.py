"""Types used by multiple modules"""

from typing import Dict, List

from src.models import Instruction, Address

InstructionList = List[Instruction]
SectionNameToInstructionsMapping = Dict[str, InstructionList]
AddressToStringMapping = Dict[Address, str]
