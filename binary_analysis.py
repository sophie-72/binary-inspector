import sys
from typing import List, Dict

from control_flow_graph import (
    print_main_function_graph,
)
from elf_utils import (
    get_file_instructions,
    get_file_relocations,
    get_file_strings,
)
from models import Instruction
from translation import translate_instructions


def write_to_file(
    executable_name: str, instructions: Dict[str, List[Instruction]]
) -> None:
    filename = f"{executable_name}.asm"

    with open(filename, "w") as file:
        for name, instructions in instructions.items():
            file.write(f"; {name}\n")

            for instruction in instructions:
                file.write(
                    f"0x{instruction.address:x}:\t{instruction.mnemonic}\t{instruction.op_str}\t; {instruction.translation}\n"
                )

            file.write(f"\n")


def main():
    instructions = get_file_instructions(executable)
    relocations = get_file_relocations(executable)
    strings = get_file_strings(executable)
    translate_instructions(instructions, relocations, strings)
    write_to_file(executable, instructions)
    print_main_function_graph(instructions, executable)


if __name__ == "__main__":
    if len(sys.argv) == 2:
        executable = sys.argv[1]
        main()
