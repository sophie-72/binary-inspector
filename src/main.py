import sys

from control_flow_graph import (
    print_main_function_graph,
)
from elf_utils import (
    get_file_instructions,
    get_file_relocations,
    get_file_strings,
)
from output import write_to_file
from translation import translate_instructions


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
