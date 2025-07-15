"""Analyzes the provided file."""

from elftools.elf.elffile import ELFFile

from src.control_flow_graph import print_main_function_graph
from src.models import ELFProcessor
from src.functions import identify_functions
from src.output import write_to_file
from src.translation import translate_instructions
from src.types import FunctionNameToFunctionMapping


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
            self.__functions: FunctionNameToFunctionMapping = {}

    def analyze(self) -> None:
        """
        Analyze the ELF file based on instructions, relocations, strings and
        function names extracted from the executable.
        """
        translate_instructions(self.__instructions, self.__relocations, self.__strings)
        write_to_file(self.__executable_name, self.__instructions)
        self.__functions = identify_functions(
            self.__instructions, self.__function_symbols
        )
        print_main_function_graph(self.__functions)

    def display_analysis(self) -> None:
        """Display the analysis results."""
        raise NotImplementedError
