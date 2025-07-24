"""Entry point of the binary-inspector project"""

import sys

from src.models.program import Program

if __name__ == "__main__":
    if len(sys.argv) == 2:
        executable = sys.argv[1]
        program = Program(executable)
        program.analyze()
        program.export_analysis()
    else:
        print("Usage: main.py <executable>")
        sys.exit(1)
