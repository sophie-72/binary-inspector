import re
from typing import List

from models import Instruction


def translate_instructions(instructions, relocations, strings) -> None:
    for name, instructions in instructions.items():
        for i in instructions:
            translate_instruction(i, instructions, relocations, strings)


def translate_instruction(
    instruction: Instruction,
    instructions: List[Instruction],
    relocations: dict,
    strings: dict,
) -> None:
    line = translate_operation(instruction, instructions)
    line = translate_pointer(line)
    line = translate_rip(line, instructions, instruction)
    line = evaluate_addition(line)
    line = translate_function_name(line, relocations)
    line = translate_strings(line, strings)
    line = translate_printable_character(line)

    instruction.translation = line


def translate_operation(instruction, instructions):
    mnemonic = instruction.mnemonic
    op_str = instruction.op_str

    two_value_operations = {
        "mov": lambda l, r: f"{l} = {r}",
        "add": lambda l, r: f"{l} = {l} + {r}",
        "adc": lambda l, r: f"{l} = {l} + {r} + carry_flag",
        "sub": lambda l, r: f"{l} = {l} - {r}",
        "or": lambda l, r: f"{l} = {l} | {r}",
        "xor": lambda l, r: (f"{l} = 0" if l == r else f"{l} = {l} ^ {r}"),
        "and": lambda l, r: f"{l} = {l} & {r}",
        "shl": lambda l, r: f"{l} = (unsigned){l} << {r}",
        "shr": lambda l, r: f"{l} = (unsigned){l} >> {r}",
        "sar": lambda l, r: f"{l} = {l} >> {r}",
        "outsb": lambda l, r: f"outport({l}, {r})",
    }

    if mnemonic in two_value_operations:
        left, right = map(str.strip, op_str.split(","))
        line = two_value_operations[mnemonic](left, right)
    elif mnemonic == "lea":
        dest, src = op_str.split(", ")
        line = f"{dest.strip()} = {src.strip()[1:-1]}"
    elif mnemonic == "call":
        line = f"call {op_str.strip()}"
    elif mnemonic == "ret":
        line = "return"
    elif mnemonic == "cmp":
        line = f"compare {op_str.strip()}"
    elif mnemonic == "je":
        previous_instruction = instructions[instructions.index(instruction) - 1]

        if previous_instruction.mnemonic in "cmp":
            left = previous_instruction.op_str.split(",")[0]
            right = previous_instruction.op_str.split(",")[1]

            line = f"if ({left} == {right}) goto {op_str.strip()}"
        elif previous_instruction.mnemonic in "test":
            left = previous_instruction.op_str.split(",")[0]
            right = previous_instruction.op_str.split(",")[1]

            line = f"if (({left} & {right}) == 0) goto {op_str.strip()}"
        else:
            line = f"if (condition) goto {op_str.strip()}"  # TODO
    elif mnemonic == "jne":
        previous_instruction = instructions[instructions.index(instruction) - 1]

        if previous_instruction.mnemonic in "cmp":
            left = previous_instruction.op_str.split(",")[0]
            right = previous_instruction.op_str.split(",")[1]

            line = f"if ({left} != {right}) goto {op_str.strip()}"
        elif previous_instruction.mnemonic in "test":
            left = previous_instruction.op_str.split(",")[0]
            right = previous_instruction.op_str.split(",")[1]

            line = f"if (({left} & {right}) != 0) goto {op_str.strip()}"
        else:
            line = f"if (!condition) goto {op_str.strip()}"  # TODO
    elif mnemonic == "jb":
        previous_instruction = instructions[instructions.index(instruction) - 1]

        if previous_instruction.mnemonic in "cmp":
            left = previous_instruction.op_str.split(",")[0]
            right = previous_instruction.op_str.split(",")[1]

            line = f"if ({left} < {right}) goto {op_str.strip()}"
        else:
            line = f"if (left < right) goto {op_str.strip()}"  # TODO
    elif mnemonic == "ja":
        previous_instruction = instructions[instructions.index(instruction) - 1]

        if previous_instruction.mnemonic in "cmp":
            left = previous_instruction.op_str.split(",")[0]
            right = previous_instruction.op_str.split(",")[1]

            line = f"if ({left} > {right}) goto {op_str.strip()}"
        else:
            line = f"if (left > right) goto {op_str.strip()}"  # TODO
    elif mnemonic == "jo":
        line = f"if (overflow_occurred) goto {op_str.strip()}"  # TODO
    elif mnemonic == "jae":
        previous_instruction = instructions[instructions.index(instruction) - 1]

        if previous_instruction.mnemonic in "cmp":
            left = previous_instruction.op_str.split(",")[0]
            right = previous_instruction.op_str.split(",")[1]

            line = f"if ({left} >= {right}) goto {op_str.strip()}"
        else:
            line = f"if (condition) goto {op_str.strip()}"  # TODO
    elif mnemonic == "jbe":
        previous_instruction = instructions[instructions.index(instruction) - 1]

        if previous_instruction.mnemonic in "cmp":
            left = previous_instruction.op_str.split(",")[0]
            right = previous_instruction.op_str.split(",")[1]

            line = f"if ({left} <= {right}) goto {op_str.strip()}"
        else:
            line = f"if (condition) goto {op_str.strip()}"  # TODO
    elif mnemonic == "js":
        line = f"if (result < 0) goto {op_str.strip()}"  # TODO
    elif mnemonic == "jmp":
        line = f"goto {op_str.strip()}"
    elif mnemonic == "test":
        line = f"test {op_str.strip()}"
    elif mnemonic == "nop":
        line = "no operation"
    elif mnemonic == "hlt":
        line = "halt"
    elif mnemonic == "endbr64":
        line = "end branch"
    elif mnemonic == "push":
        line = f"stack.push({op_str.strip()})"
    elif mnemonic == "pop":
        line = f"{op_str.strip()} = stack.pop()"
    elif mnemonic == "leave":
        line = "leave"
    elif mnemonic == "loopne":
        line = "loopne"  # TODO
    else:
        raise KeyError(f"Unknown mnemonic: {mnemonic}")

    return line


def translate_pointer(line):
    if "qword ptr [" in line:
        line = line.replace("qword ptr [", "memory[")

    if "byte ptr [" in line:
        line = line.replace("byte ptr [", "memory[")

    return line


def translate_rip(line, instructions, i):
    if "rip" in line:
        next_instruction = instructions[instructions.index(i) + 1]
        next_instruction_addr = next_instruction.address
        line = line.replace("rip", hex(next_instruction_addr))

    return line


def evaluate_addition(line):
    hex_addition = re.search("0x[0-9a-f]+\\s\\+\\s0x[0-9a-f]+", line)
    if hex_addition:
        result = eval(hex_addition.group())
        line = line.replace(hex_addition.group(), hex(result))

    return line


def translate_function_name(line, relocations):
    hex_address_match_pattern = "0x[0-9a-f]+"
    memory = re.search(f"memory\\[{hex_address_match_pattern}+]", line)
    if memory:
        hex_address = re.search(hex_address_match_pattern, memory.group())
        function_name = relocations.get(hex_address.group())

        if function_name:
            line = line.replace(memory.group(), function_name)

    return line


def translate_strings(line, strings):
    hex_address_match_pattern = "0x[0-9a-f]+"
    address = re.search(hex_address_match_pattern, line)
    if address:
        string = strings.get(address.group())

        if string:
            line = line.replace(address.group(), '"' + string + '"')

    return line


def translate_printable_character(line):
    hex_character = re.search("0x[0-9a-f]{2}$", line)
    if hex_character:
        decimal_value = int(hex_character.group(), 16)

        if 32 <= decimal_value <= 126:
            character = chr(decimal_value)
            line = line.replace(hex_character.group(), character)

    return line
