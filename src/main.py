"""Entry point of the binary-inspector project."""

import sys

from elftools.elf.elffile import ELFFile

from src.control_flow_graph import (
    print_main_function_graph,
)

# from src.pattern_analysis import print_pattern_analysis
from src.elf_utils import (
    ELFProcessor,
)
from src.output import write_to_file
from src.translation import translate_instructions


if __name__ == "__main__":
    if len(sys.argv) == 2:
        executable = sys.argv[1]
        with open(executable, "rb") as f:
            elffile = ELFFile(f)
            elf_processor = ELFProcessor(elffile)
            instructions = elf_processor.get_file_instructions()
            relocations = elf_processor.get_file_relocations()
            strings = elf_processor.get_file_strings()
            function_symbols = elf_processor.get_function_symbols()

        translate_instructions(instructions, relocations, strings)
        write_to_file(executable, instructions)
        print_main_function_graph(instructions, function_symbols)
    else:
        print("Usage: main.py <executable>")
        sys.exit(1)
