"""Write program output to a file."""

from src.types import SectionNameToInstructionsMapping


def write_to_file(
    executable_name: str, instructions: SectionNameToInstructionsMapping
) -> None:
    """
    Write assembly instructions and translations to a file.
    :param executable_name: The ELF file name.
    :param instructions: A dictionary mapping section names to lists of instructions.
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
                        f"{instruction.address.to_hex_string()}:\t"
                        f"{instruction.mnemonic}\t"
                        f"{instruction.op_str}\t"
                        f"{translation}\n"
                    )
