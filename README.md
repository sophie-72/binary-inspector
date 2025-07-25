# Binary Inspector

A disassembler and control flow analyzer for ELF binaries written in Python.
It extracts assembly instructions, strings, and function names; identifies functions and basic blocks; and builds control flow graphs to provide insight into the structure of compiled programs.

## Motivation

I created **Binary Inspector** to deepen my understanding of how disassemblers and control flow analysis tools work under the hood.
This project was an educational exercise in binary analysis, ELF parsing, and control flow graph construction.

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
   **Note**: You also need to install [Graphviz](https://graphviz.org/download/) separately.

## Usage

To analyze an ELF binary, run the following command:

```bash
python -m src.main <executable>
```

### Example

An example is provided in the `example` directory.
The `example.c` file contains the source code, and `example` is the compiled program.
You can compile the example yourself or use the provided binary directly.
If you just want to see the analysis results, these are available in the `output/example` directory.

To compile the example program, use:

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
