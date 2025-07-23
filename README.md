# Binary Inspector

A disassembler and control flow analyzer for ELF binaries written in Python.
It extracts assembly instructions, strings, and function names; identifies functions and basic blocks; and builds control flow graphs to provide insight into the structure of compiled programs.

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/sophie-72/binary-inspector
   cd binary-inspector
   ```

2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

## Usage

To analyze an ELF binary, run the following command:

```bash
python -m src.main <executable>
```

### Example

An example is provided in the `example` directory.
The `example.c` file contains the source code, and `example` is the compiled program.
You can compile the example yourself or use the provided binary directly.

To compile the test program, use:

```bash
gcc -o example/example example/example.c
```

Then, analyze the binary with:

```bash
python -m src.main example/example
```

## Acknowledgments

As I had no previous experience with the `pyelftools` and `capstone` libraries and was unfamiliar with the structure of ELF files, I used AI tools to guide me through this project.

The `example.c` file was also generated with the help of AI.
