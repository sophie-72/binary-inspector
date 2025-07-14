"""Analyzes the provided file."""

from builtins import _NotImplementedType

from elftools.elf.elffile import ELFFile

from src.control_flow_graph import print_main_function_graph
from src.elf_utils import ELFProcessor
from src.functions import identify_functions
from src.output import write_to_file
from src.pattern_analysis import print_pattern_analysis
from src.translation import translate_instructions


class Program:
    """Analyzes the provided file."""

    def __init__(self, executable_name):
        self.__executable_name = executable_name

        with open(executable_name, "rb") as f:
            elffile = ELFFile(f)
            elf_processor = ELFProcessor(elffile)
            self.__instructions = elf_processor.get_file_instructions()
            self.__relocations = elf_processor.get_file_relocations()
            self.__strings = elf_processor.get_file_strings()
            self.__function_symbols = elf_processor.get_function_names()

    def analyze(self) -> None:
        translate_instructions(self.__instructions, self.__relocations, self.__strings)
        write_to_file(self.__executable_name, self.__instructions)
        functions = identify_functions(self.__instructions, self.__function_symbols)
        print_main_function_graph(functions)
        for function_name, function in functions.items():
            print_pattern_analysis(function)

    def display_analysis(self) -> _NotImplementedType:
        return NotImplemented
