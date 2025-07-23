"""Write program output to a file."""

import os

from graphviz import Digraph  # type: ignore

from src.custom_types import (
    SectionNameToInstructionsMapping,
    FunctionNameToFunctionMapping,
)
from src.models.function import Function


def write_instructions_to_file(
    executable_name: str, instructions: SectionNameToInstructionsMapping
) -> None:
    """
    Write assembly instructions and translations to a file.
    :param executable_name: The ELF file path.
    :param instructions: A dictionary mapping section names to lists of instructions.
    """

    output_directory = _get_output_directory(executable_name)
    filename = f"{output_directory}.asm"

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

    print(f"Instructions of the .text section written to {filename}")


def export_all_control_flow_graphs(
    executable_name: str,
    functions: FunctionNameToFunctionMapping,
) -> None:
    """
    Export all control flow graphs to PNG files.
    :param executable_name: The ELF file path.
    :param functions: A dictionary mapping function names to functions.
    """
    output_directory = _get_output_directory(executable_name)

    for function in functions.values():
        _export_function_control_flow_graph(function, output_directory)


def _export_function_control_flow_graph(
    function: Function, output_directory: str
) -> None:
    dot = Digraph(comment=f"CFG for {function.name}")

    for i, block in enumerate(function.basic_blocks):
        instructions_rows = ""
        for instruction in block.instructions:
            translation = (
                f"{instruction.translation}" if instruction.translation else ""
            )
            instructions_rows += (
                "<tr>"
                f"<td align='left'>{instruction.address.to_hex_string()}</td>"
                f"<td align='left'>{instruction.mnemonic}</td>"
                f"<td align='left'>{instruction.op_str}</td>"
                f"<td align='left'>{translation}</td>"
                "</tr>"
            )
        label = f"""<
                    <table border="0" cellborder="1" cellspacing="0" cellpadding="4">
                        <tr>
                            <td colspan="4" bgcolor="lightgray"><b>Block {i}</b></td>
                        </tr>
                        <tr>
                            <td><b>Address</b></td>
                            <td><b>Mnemonic</b></td>
                            <td><b>Operands</b></td>
                            <td><b>Translation</b></td>
                        </tr>
                        {instructions_rows}
                    </table>
                >"""
        dot.node(name=str(i), label=label, shape="none")

    for i, block in enumerate(function.basic_blocks):
        for successor in block.successors:
            j = function.basic_blocks.index(successor)
            dot.edge(str(i), str(j))

    filename = f"{output_directory}/{function.name}"
    dot.render(filename, cleanup=True, format="png")

    print(f"Control flow graph of the {function.name} function saved to {filename}.png")


def _get_output_directory(executable_name: str) -> str:
    output_directory = os.path.join("output", executable_name)
    os.makedirs(output_directory, exist_ok=True)
    return output_directory
