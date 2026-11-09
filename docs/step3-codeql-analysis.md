# Step 3 — Static Security Analysis with CodeQL

## Overview

This phase examines the intentionally vulnerable C file parser using **GitHub CodeQL**, a static analysis tool. Unlike AFL++, which runs the program with mutated inputs, CodeQL builds a structured database of source-code relationships and evaluates security queries against that database.

The objective is to identify possible security issues and compare static analysis findings with the results from AFL++, AddressSanitizer (ASan), and GDB.

## Environment

| Component | Configuration |
|---|---|
| Operating system | Ubuntu Linux (VirtualBox) |
| Source analyzed | `parser.c` |
| CodeQL CLI | 2.25.5 |
| Language extractor | `cpp` (C/C++) |
| Query pack | `codeql/cpp-queries` 1.6.3 |
| Query suite | `cpp-security-and-quality` |
| Output format | SARIF |

## Analysis procedure

### 1. Verify the CodeQL installation

```bash
codeql version
codeql resolve languages
codeql resolve packs | grep 'codeql/cpp'
```

The installed distribution recognized the `cpp` extractor and the C/C++ query packs.

### 2. Build a CodeQL database

From the project root:

```bash
mkdir -p build
codeql database create codeql-db \
  --language=cpp \
  --source-root=. \
  --command="gcc -g -O0 -c parser.c -o build/parser_codeql.o"
```

**Result:** CodeQL reported that the database was successfully created. The compilation command allows CodeQL to extract information from the C source file.

### 3. Run the security-and-quality queries

```bash
mkdir -p codeql-results
codeql database analyze codeql-db \
  codeql/cpp-queries:codeql-suites/cpp-security-and-quality.qls \
  --format=sarif-latest \
  --output=codeql-results/results.sarif \
  --threads=2
```

The generated `results.sarif` was approximately 148 KB. The scan returned **one finding**.

## Finding: Potential path injection

| Attribute | Result |
|---|---|
| Rule ID | `cpp/path-injection` |
| Findings reported | 1 |
| Source | Command-line argument used as a file path |
| File operation | `fopen()` |
| Status | Requires context-specific review |

CodeQL message:

> This argument to a file access function is derived from user input (a command-line argument) and then passed to fopen(__filename).

Relevant code in `parser.c`:

```c
FILE *file = fopen(argv[1], "rb");
```

The file path comes directly from `argv[1]`. The program does not restrict it to an approved directory. In applications where an untrusted user can supply that value and file access must be limited, this pattern may allow access to unintended paths, subject to the process's operating-system permissions.

**Assessment in this project:** The parser is a local command-line lab tool intentionally designed to open a file supplied by the person running it. Therefore, the CodeQL finding is a **potential security concern**, not proof of an exploitable path-injection vulnerability in this threat model. A production service accepting untrusted filenames would need an explicit file-access policy and corresponding validation or isolation.

## Comparison with dynamic testing

| Tool | Observed result |
|---|---|
| AFL++ | Generated a crashing input during fuzzing; one unique crash saved |
| AddressSanitizer | Reproduced and reported `stack-buffer-overflow` |
| GDB | Showed `length = 37`, `size = 42`, and a 32-byte destination buffer |
| CodeQL | Reported one potential `cpp/path-injection` issue |

The stack buffer overflow occurs at:

```c
unsigned char buffer[32];
memcpy(buffer, input + 5, length);
```

Because `length` can exceed 32, the copy may write beyond the destination. The AFL++ crash used a **37-byte** copy into a **32-byte** buffer, an attempted overflow of **5 bytes**.

**Important limitation:** The selected CodeQL query suite **did not report this known buffer overflow**. A static scan with no corresponding finding does not mean the program is free of that vulnerability; tool results depend on the available queries and their analysis capabilities.

## Conclusion

This experiment illustrates why static and dynamic analysis should be used together. AFL++, ASan, and GDB established the actual memory-safety failure, while CodeQL identified a separate code pattern that merits review under an appropriate threat model.

**Next phase:** Preserve `parser.c` as the intentionally vulnerable baseline, implement a separate `secure_parser.c` with destination-size validation, and retest it using the same AFL++ crash input and ASan instrumentation.

---

*Educational security lab. All tests were performed against an intentionally vulnerable local program.*

