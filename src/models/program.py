"""Analyzes the provided file."""

from dataclasses import dataclass
from typing import Optional

from elftools.elf.elffile import ELFFile

from src.constants import RETURN_MNEMONIC
from src.custom_types import (
    FunctionNameToFunctionMapping,
    InstructionList,
    AddressToStringMapping,
    SectionNameToInstructionsMapping,
)
from src.models import ELFProcessor, Address, Function
from src.output import write_to_file, display_functions_control_flow_graph
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
    def functions(self) -> FunctionNameToFunctionMapping:
        """Get the program's functions."""
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
        write_to_file(self.__executable_name, self.__instructions)
        self.__functions = self.identify_functions()

    def display_analysis(self) -> None:
        """Display the analysis results."""
        display_functions_control_flow_graph(self.functions)

    def identify_functions(self) -> FunctionNameToFunctionMapping:
        """
        Identify functions from instructions and function symbols.
        :return: A dictionary mapping function names to function objects.
        """
        functions = {}

        sorted_addresses = sorted(self.__function_symbols.keys(), key=lambda x: x.value)

        for section_instructions in self.__instructions.values():
            for function_address in sorted_addresses:
                function_name = self.__function_symbols[function_address]

                function_start_index = _get_function_start_index(
                    section_instructions, function_address
                )

                if function_start_index is not None:
                    function_end_index = _get_function_end_index(
                        function_start_index,
                        section_instructions,
                        self.__function_symbols,
                        function_address,
                    )

                    function_instructions = section_instructions[
                        function_start_index : function_end_index + 1
                    ]
                    current_function = Function(
                        function_name, function_address, function_instructions
                    )
                    current_function.identify_basic_blocks()
                    current_function.identify_successors_and_predecessors()

                    functions[function_name] = current_function

        return functions


def _get_function_start_index(
    section_instructions: InstructionList, function_address: Address
):
    function_start_index = None
    for i, instruction in enumerate(section_instructions):
        if instruction.address == function_address:
            function_start_index = i
            break

    return function_start_index


def _get_function_end_index(
    function_start_index: int,
    section_instructions: InstructionList,
    function_symbols: AddressToStringMapping,
    function_address: Address,
):
    function_end_index = function_start_index
    for j in range(function_start_index + 1, len(section_instructions)):
        instruction = section_instructions[j]

        # Stop if we hit another function
        if (
            instruction.address in function_symbols
            and instruction.address != function_address
        ):
            break

        function_end_index = j
        if instruction.mnemonic == RETURN_MNEMONIC:
            break

    return function_end_index
