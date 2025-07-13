"""Types used by multiple modules"""

from typing import Dict, List

from src.models import Instruction

InstructionList = List[Instruction]
SectionNameToInstructionsMapping = Dict[str, InstructionList]
AddressToStringMapping = Dict[str, str]
