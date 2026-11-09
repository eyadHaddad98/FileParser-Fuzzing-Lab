# Step 2 — Crash Analysis with GDB and AddressSanitizer

## Objective

Reproduce the AFL++-generated crash from Step 1, inspect the binary input and parser variables with GDB, and identify the exact cause of the memory-safety violation.

## Tools and Environment

- **Operating system:** Ubuntu Linux in VirtualBox
- **Debugger:** GNU GDB 17.1
- **Compiler:** `afl-clang-fast` (AFL++ 4.40c)
- **Memory error detector:** AddressSanitizer (ASan)
- **Source:** `parser.c`
- **Vulnerable operation:** `memcpy()` at `parser.c:38`
- **Classification:** CWE-121 — Stack-based Buffer Overflow

## Crash Input

AFL++ saved a crashing test case in `fuzz_output_round2/default/crashes/` (a file named `id:000000,...`). The file is **42 bytes** long. GDB confirmed that the fifth byte (`input[4]`) has value `0x25` (37 decimal).

The custom file format is:

| Field | Bytes | Meaning |
| --- | ---: | --- |
| `FUZ1` magic header | 4 | Expected file signature |
| Payload length | 1 | `0x25` = 37 |
| Payload | 37 | Data requested for copying |
| **Total** | **42** | 4 + 1 + 37 |

The first 16 bytes observed in GDB were:

```text
0x46 0x55 0x5a 0x31 0x25 0x68 0x65 0x6c
0x6c 0x6f 0x41 0x41 0x41 0x41 0x41 0x41
```

These start with `FUZ1`, the length byte `0x25`, and payload bytes including `helloAAAAAA`.

## Reproducing the Crash

From the project root:

```bash
CRASH=$(find fuzz_output_round2/default/crashes \
  -maxdepth 1 -type f -name 'id:*' -print -quit)

./build/parser_afl "$CRASH"
```

AddressSanitizer reported:

```text
ERROR: AddressSanitizer: stack-buffer-overflow
WRITE of size 37
#1 ... main ... parser.c:38:5
[1184, 1216) 'buffer' (line 35)
Memory access at offset 1216 overflows this variable
```

The numeric memory addresses and process IDs may change between runs; the source location and bounds violation are the relevant findings.

## Debug Build and Breakpoint

The original fuzzing binary was compiled with `-O1`, which made some local variables unavailable in GDB. A separate debug binary was built without optimization:

```bash
AFL_USE_ASAN=1 afl-clang-fast -g -O0 \
  -fno-omit-frame-pointer \
  parser.c -o build/parser_gdb
```

Then GDB was started with the saved crash input:

```bash
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
  gdb -q --args ./build/parser_gdb "$CRASH"
```

At the GDB prompt:

```gdb
break parser.c:38
run
```

GDB stopped before the vulnerable copy:

```text
Breakpoint 1, main (...) at parser.c:38
38    memcpy(buffer, input + 5, length);
```

## Variable Inspection

GDB produced the following results:

```text
(gdb) print length
$1 = 37 '%'
(gdb) print size
$2 = 42
(gdb) print sizeof(buffer)
$3 = 32
(gdb) print (int)length - (int)sizeof(buffer)
$4 = 5
```

| Value | Observed | Interpretation |
| --- | ---: | --- |
| `length` | 37 bytes | Untrusted requested copy length |
| `size` | 42 bytes | Bytes read from input file |
| `sizeof(buffer)` | 32 bytes | Destination capacity |
| `length - sizeof(buffer)` | **5 bytes** | Attempted write beyond the destination |

The output `37 '%'` is GDB's representation of the numeric value 37 and its printable ASCII character `%`.

## Root Cause

The vulnerable code is:

```c
uint8_t length = input[4];

if (size < 5 + (size_t)length) {
    printf("Incomplete file\n");
    return 1;
}

unsigned char buffer[32];
memcpy(buffer, input + 5, length);
```

The existing validation checks only whether the **source file** has enough bytes. It does not check whether the **destination buffer** has enough capacity.

For the saved AFL++ input:

- Source file contains `5 + 37 = 42` bytes, so the input-length check passes.
- Destination buffer capacity is 32 bytes.
- `memcpy` attempts to write 37 bytes, exceeding the destination by **5 bytes**.

This is a **stack-based buffer overflow (CWE-121)** caused by trusting an input-controlled length without checking it against the destination size.

## Crash and Backtrace

After GDB continued past the breakpoint, AddressSanitizer detected the invalid write and aborted the program with `SIGABRT`. The GDB backtrace included:

```text
#4  __GI_abort ()
#5  __sanitizer::Abort()
...
#9  __asan_memcpy ()
#10 main (...) at parser.c:38
```

This trace shows the program was terminated by AddressSanitizer after the invalid memory operation. The stop in `pthread_kill.c`, and the notice that its source file is unavailable, relate to libc's abort implementation; they do **not** indicate another parser vulnerability.

## Conclusion and Next Actions

The AFL++-generated crash was reproduced and investigated using GDB and ASan. The precise cause is a 37-byte copy into a 32-byte stack buffer, resulting in an attempted 5-byte out-of-bounds write at `parser.c:38`.

The vulnerable implementation remains unchanged at this stage so subsequent analysis can use it as a baseline.

**Next steps:** perform static analysis with CodeQL; implement a destination-size check in a separate secure version; rerun the crashing input and regression tests to verify the fix.

> Educational security lab: the intentionally vulnerable parser is for controlled testing only.

