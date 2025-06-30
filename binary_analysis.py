import sys
import re

from capstone import *
from elftools.elf.elffile import ELFFile


def get_file_instructions(filename):
    with open(filename, "rb") as f:
        elffile = ELFFile(f)

        code = elffile.get_section_by_name(".text")
        opcodes = code.data()
        addr = code["sh_addr"]

        md = Cs(CS_ARCH_X86, CS_MODE_64)

        instructions = []
        for i in md.disasm(opcodes, addr):
            instructions.append(i)

        return instructions


def translate_operation(instruction, instructions):
    mnemonic = instruction.mnemonic
    op_str = instruction.op_str

    two_value_operations = {
        "mov": lambda l, r: f"{l} = {r}",
        "add": lambda l, r: f"{l} += {r}",
        "sub": lambda l, r: f"{l} -= {r}",
        "xor": lambda l, r: (f"{l} = 0" if l == r else f"{l} ^= {r}"),
        "and": lambda l, r: f"{l} &= {r}",
        "or": lambda l, r: f"{l} |= {r}",
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
            line = f"if (condition) goto {op_str.strip()}"
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
            line = f"if (!condition) goto {op_str.strip()}"
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
    else:
        line = f"{mnemonic}"

    return line


def translate_pointer(line):
    if "qword ptr [" in line:
        line = line.replace("qword ptr [", "memory[")

    if "byte ptr [" in line:
        line = line.replace("byte ptr [", "memory[")

    return line


def translate_instructions(instructions):
    translated_instructions = []
    for i in instructions:
        line = translate_operation(i, instructions)
        line = translate_pointer(line)

        if "rip" in line:
            next_instruction = instructions[instructions.index(i) + 1]
            next_instruction_addr = next_instruction.address
            line = line.replace("rip", hex(next_instruction_addr))

        hex_addition = re.search("0x[0-9a-f]+\\s\\+\\s0x[0-9a-f]+", line)
        if hex_addition:
            result = eval(hex_addition.group())
            line = line.replace(hex_addition.group(), hex(result))

        hex_character = re.search("0x[0-9a-f]{2}$", line)
        if hex_character:
            decimal_value = int(hex_character.group(), 16)

            if 32 <= decimal_value <= 126:
                character = chr(decimal_value)
                line = line.replace(hex_character.group(), character)

        translated_instructions.append(line)
    return translated_instructions


def write_to_file(executable_name, instructions, translated_instructions):
    filename = f"{executable_name}.asm"

    with open(filename, "w") as file:
        for instruction, translated_instruction in zip(
            instructions, translated_instructions
        ):
            file.write(
                f"0x{instruction.address:x}:\t{instruction.mnemonic}\t{instruction.op_str}\t; {translated_instruction}\n"
            )


def main():
    instructions = get_file_instructions(sys.argv[1])
    translated_instructions = translate_instructions(instructions)
    write_to_file(sys.argv[1], instructions, translated_instructions)


if __name__ == "__main__":
    if len(sys.argv) == 2:
        main()
