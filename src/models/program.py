"""Analyzes the provided file."""

from dataclasses import dataclass
from typing import Optional

from elftools.elf.elffile import ELFFile

from src.custom_types import (
    FunctionNameToFunctionMapping,
    AddressToStringMapping,
    SectionNameToInstructionsMapping,
)
from src.functions_identification import identify_functions
from src.models import ELFProcessor
from src.output import write_instructions_to_file, export_all_control_flow_graphs
from src.translation import translate_instructions


@dataclass
class FileContent:
    """ELF file content (currently only used in tests)."""

    instructions: Optional[SectionNameToInstructionsMapping] = None
    relocations: Optional[AddressToStringMapping] = None
    strings: Optional[AddressToStringMapping] = None
    function_symbols: Optional[AddressToStringMapping] = None


class Program:
    """Analyzes the provided file."""

    def __init__(
        self,
        executable_name: Optional[str] = None,
        file_content: Optional[FileContent] = None,
    ):
        if executable_name:
            self.__executable_name = executable_name
            with open(executable_name, "rb") as f:
                elffile = ELFFile(f)
                elf_processor = ELFProcessor(elffile)
                self.__instructions = elf_processor.get_file_instructions()
                self.__relocations = elf_processor.get_file_relocations()
                self.__strings = elf_processor.get_file_strings()
                self.__function_symbols = elf_processor.get_function_names()
        elif file_content:
            self.__executable_name = ""
            self.__instructions = file_content.instructions or {}
            self.__relocations = file_content.relocations or {}
            self.__strings = file_content.strings or {}
            self.__function_symbols = file_content.function_symbols or {}
        else:
            raise RuntimeError(
                "Either an executable name or a file content must be provided."
            )

        self.__functions: FunctionNameToFunctionMapping = {}

    @property
    def instructions(self) -> SectionNameToInstructionsMapping:
        """Get the program instructions."""
        return self.__instructions

    @property
    def relocations(self) -> AddressToStringMapping:
        """Get the program relocations."""
        return self.__relocations

    @property
    def strings(self) -> AddressToStringMapping:
        """Get the program strings."""
        return self.__strings

    @property
    def function_symbols(self) -> AddressToStringMapping:
        """Get the program function symbols."""
        return self.__function_symbols

    @property
    def functions(self) -> FunctionNameToFunctionMapping:
        """Get the program functions."""
        return self.__functions

    def analyze(self) -> None:
        """
        Analyze the ELF file based on instructions, relocations, strings and
        function names extracted from the executable.
        """
        translate_instructions(
            self.__instructions,
            self.__relocations,
            self.__function_symbols,
            self.__strings,
        )
        self.__functions = identify_functions(
            self.__instructions, self.__function_symbols
        )

    def export_analysis(self) -> None:
        """Export the analysis results."""
        write_instructions_to_file(self.__executable_name, self.__instructions)
        export_all_control_flow_graphs(self.__executable_name, self.functions)
