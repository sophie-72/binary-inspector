import sys
import re

from capstone import *
from elftools.elf.elffile import ELFFile


def get_file_instructions(filename):
    with open(filename, 'rb') as f:
        elffile = ELFFile(f)

        code = elffile.get_section_by_name('.text')
        opcodes = code.data()
        addr = code['sh_addr']

        md = Cs(CS_ARCH_X86, CS_MODE_64)

        instructions = []
        for i in md.disasm(opcodes, addr):
            instructions.append(i)

        return instructions

def get_pseudocode(instructions):
        pseudocode = []
        for i in instructions:
            addr = i.address
            mnemonic = i.mnemonic
            op_str = i.op_str

            if "rip" in op_str:
                next_instruction = instructions[instructions.index(i) + 1]
                next_instruction_addr = next_instruction.address
                op_str = op_str.replace("rip", hex(next_instruction_addr))

            hex_addition = re.search("0x[0-9a-f]+\\s\\+\\s0x[0-9a-f]+", op_str)
            if hex_addition:
                result = eval(hex_addition.group())
                op_str = op_str.replace(hex_addition.group(), hex(result))

            if "qword ptr [" in op_str:
                op_str = op_str.replace("qword ptr [","memory[")

            if mnemonic == 'mov':
                line = f"{op_str.split(',')[0].strip()} = {op_str.split(',')[1].strip()}"
            elif mnemonic == 'add':
                line = f"{op_str.split(',')[0].strip()} += {op_str.split(',')[1].strip()}"
            elif mnemonic == 'sub':
                line = f"{op_str.split(',')[0].strip()} -= {op_str.split(',')[1].strip()}"

            elif mnemonic == 'xor':
                left = op_str.split(',')[0].strip()
                right = op_str.split(',')[1].strip()

                if left == right:
                    line = f"{left} = 0"
                else:
                    line = f"{left} ^= {right}"

            elif mnemonic == 'and':
                line = f"{op_str.split(',')[0].strip()} &= {op_str.split(',')[1].strip()}"

            elif mnemonic == 'or':
                line = f"{op_str.split(',')[0].strip()} |= {op_str.split(',')[1].strip()}"

            elif mnemonic == 'lea':
                dest, src = op_str.split(', ')
                line = f"{dest.strip()} = address_of({src.strip()})"

            elif mnemonic == 'call':
                line = f"call {op_str.strip()}"

            elif mnemonic == 'ret':
                line = "return"

            elif mnemonic == 'cmp':
                line = f"compare {op_str.strip()}"

            elif mnemonic == 'je':
                line = f"if (condition) goto {op_str.strip()}"

            elif mnemonic == 'jne':
                line = f"if (!condition) goto {op_str.strip()}"

            elif mnemonic == 'jmp':
                line = f"goto {op_str.strip()}"

            elif mnemonic == 'test':
                line = f"test {op_str.strip()}"

            elif mnemonic == 'nop':
                line = "no operation"

            elif mnemonic == 'hlt':
                line = "halt"

            elif mnemonic == 'endbr64':
                line = "end branch"
            elif mnemonic == 'push':
                line = f"stack.push({op_str.strip()})"
            elif mnemonic == 'pop':
                line = f"{op_str.strip()} = stack.pop()"
            else:
                line = f"{mnemonic}"

            print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
            print(f"0x{addr:x}:\t{line}\n")
            pseudocode.append(line)
        return pseudocode

def main():
    instructions = get_file_instructions(sys.argv[1])
    get_pseudocode(instructions)

if __name__ == '__main__':
    if len(sys.argv) == 2:
        main()