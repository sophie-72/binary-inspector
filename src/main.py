"""Entry point of the binary-inspector project."""

import sys

from src.control_flow_graph import (
    print_main_function_graph,
    _get_functions,
)

from src.elf_utils import (
    get_file_instructions,
    get_file_relocations,
    get_file_strings,
)
from src.output import write_to_file
from src.translation import translate_instructions


if __name__ == "__main__":
    if len(sys.argv) == 2:
        executable = sys.argv[1]
        instructions = get_file_instructions(executable)
        relocations = get_file_relocations(executable)
        strings = get_file_strings(executable)
        translate_instructions(instructions, relocations, strings)
        write_to_file(executable, instructions)
        print_main_function_graph(instructions, executable)

        """
        functions = _get_functions(instructions, executable)
        for function_name, function in functions.items():
            if function.name == "main":
                print_pattern_analysis(function)
                break
        """
    else:
        print("Usage: main.py <executable>")
        sys.exit(1)
