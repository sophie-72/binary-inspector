from typing import List, Dict

from models import Instruction


def write_to_file(
    executable_name: str, instructions: Dict[str, List[Instruction]]
) -> None:
    filename = f"{executable_name}.asm"

    with open(filename, "w") as file:
        for name, instructions in instructions.items():
            if name == ".text":
                for instruction in instructions:
                    file.write(
                        f"0x{instruction.address:x}:\t{instruction.mnemonic}\t{instruction.op_str}\t; {instruction.translation}\n"
                    )
