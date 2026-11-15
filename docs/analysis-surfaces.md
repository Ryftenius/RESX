# Analysis surfaces

RESX analyzes hostile Windows PE files without ever loading or running them. This is
what it looks at, and how far each piece goes.

## PE Structure

The parser validates DOS/NT headers, optional headers, section mappings, data
directories, imports, exports, relocations, resources, TLS, load configuration, debug
records, CLR metadata, certificates and x64 exception/unwind data.

If the file doesn't actually back some bytes, they stay unavailable. They never get
filled in as zeroes.

## Disassembly And Functions

Function discovery pulls from exports, symbols, runtime-function records, startup
metadata, direct call targets, validated thunks, and a bounded fallback over executable
sections. Disassembly uses exact RVA/file mappings and keeps import slots separate from
the bodies of imported functions.

Function types come from the PDB when there is one. Without a PDB, a bounded static ABI
pass guesses machine-width arguments, pointer access and return values. Anything it
can't work out (signedness, names, layouts, unused arguments) is shown as unknown.

`--ssa` turns on lightweight SSA annotations. They're off by default.

## Control Flow

RESX builds function CFGs, follows direct control flow within budget, recovers common
switch forms, and records indirect edges it couldn't resolve. It also rebuilds the
startup roots the loader sees, like the entry point and TLS callbacks. Budgets and
incomplete edges show up in the output.

When direct control flow lands in the middle of bytes already decoded another way, both
instruction streams are kept as separate decode evidence. The details are only shown
with `--verbose` or in structured dump output. Overlapping decodes on their own don't
mean the code is obfuscated.

## Static Behavior

Behavior and contract reports tie together exact imports, the local code producing each
argument, constants, strings and instruction evidence. Categories cover IPC, network,
crypto, executable-memory APIs, anti-debugging, drivers, IOCTL/NDIS, hypervisor
instructions and persistence APIs.

These are static findings. They tell you what the code *can* do, not that it ran or
worked.

## Search And Comparison

YARA-compatible rules and `find` locate bounded byte, string, constant and instruction
evidence.

`diff`, `index` and `hunt` compare normalized functions, CFG shape, API sets, constants,
fuzzy hashes and metadata. Similarity scores rank candidates. A high score means
"look at this one first", not "these are the same binary".

## Explicit Decoding

`payload` applies the codecs or AES-CBC parameters you choose, within limits, and hashes
every layer. It won't guess a missing key.
