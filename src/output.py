"""Write program output to a file."""

from typing import List, Dict

from models import Instruction


def write_to_file(
    executable_name: str, instructions: Dict[str, List[Instruction]]
) -> None:
    """
    Write assembly instructions and translations to a file.
    :param executable_name: ELF file name
    :param instructions: dictionary of instructions by section name
    """
    filename = f"{executable_name}.asm"

    with open(filename, "w", encoding="utf-8") as file:
        for section_name, section_instructions in instructions.items():
            if section_name == ".text":
                for instruction in section_instructions:
                    translation = (
                        f"; {instruction.translation}"
                        if instruction.translation
                        else ""
                    )
                    file.write(
                        f"0x{instruction.address:x}:\t"
                        f"{instruction.mnemonic}\t"
                        f"{instruction.op_str}\t"
                        f"{translation}\n"
                    )
