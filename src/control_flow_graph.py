"""Print the control flow graph of the functions."""

from src.models import Function
from src.types import FunctionNameToFunctionMapping


def print_main_function_graph(
    functions: FunctionNameToFunctionMapping,
) -> None:
    """
    Print the control flow graph elements of the main function.
    :param functions: A dictionary mapping function names to functions.
    """
    for function in functions.values():
        _print_control_flow_graph(function)


def _print_control_flow_graph(function: Function) -> None:
    print(f"\nControl Flow Graph for {function.name}:")
    print("=" * 50)

    for i, block in enumerate(function.basic_blocks):
        print(
            f"Block {i}: "
            f"{block.start_address.to_hex_string()} - {block.end_address.to_hex_string()}"
        )
        print(f"  Instructions: {len(block.instructions)}")
        print(f"  Successors: {len(block.successors)}")
        print(f"  Predecessors: {len(block.predecessors)}")

        for succ in block.successors:
            succ_index = function.basic_blocks.index(succ)
            print(f"    -> Block {succ_index} ({succ.start_address.to_hex_string()})")

        for pred in block.predecessors:
            pred_index = function.basic_blocks.index(pred)
            print(f"    <- Block {pred_index} ({pred.start_address.to_hex_string()})")

        print()
