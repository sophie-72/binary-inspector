from elftools.elf.elffile import ELFFile

from src.control_flow_graph import print_main_function_graph
from src.elf_utils import ELFProcessor
from src.output import write_to_file
from src.translation import translate_instructions


class Program:
    def __init__(self, executable_name):
        with open(executable_name, "rb") as f:
            elffile = ELFFile(f)
            elf_processor = ELFProcessor(elffile)
            instructions = elf_processor.get_file_instructions()
            relocations = elf_processor.get_file_relocations()
            strings = elf_processor.get_file_strings()
            function_symbols = elf_processor.get_function_names()

        translate_instructions(instructions, relocations, strings)
        write_to_file(executable_name, instructions)
        print_main_function_graph(instructions, function_symbols)
