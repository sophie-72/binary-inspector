"""Write program output to a file."""

import streamlit as st
from graphviz import Digraph  # type: ignore

from src.custom_types import (
    SectionNameToInstructionsMapping,
    FunctionNameToFunctionMapping,
)


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


def display_functions_control_flow_graph(
    functions: FunctionNameToFunctionMapping,
) -> None:
    st.title("Binary Inspector: Control Flow Graph Visualizer")

    function_names = list(functions.keys())
    selected_function = st.selectbox("Select a function", function_names)

    function = functions[selected_function]

    dot = Digraph(comment=f"CFG for {selected_function}")

    for i, block in enumerate(function.basic_blocks):
        instructions = ""
        for instruction in block.instructions:
            translation = (
                f"; {instruction.translation}" if instruction.translation else ""
            )
            instructions += (
                f"{instruction.address.to_hex_string()}:\t"
                f"{instruction.mnemonic}\t"
                f"{instruction.op_str}\t"
                f"{translation}\n"
            )
        label = f"Block {i}\\n{instructions}"
        dot.node(str(i), label)

    for i, block in enumerate(function.basic_blocks):
        for successor in block.successors:
            j = function.basic_blocks.index(successor)
            dot.edge(str(i), str(j))

    st.graphviz_chart(dot)
