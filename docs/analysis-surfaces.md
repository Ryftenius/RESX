# Analysis surfaces

RESX analyzes hostile Windows PE files without loading or executing them.

## PE structure

The parser validates DOS/NT headers, optional headers, section mappings, data
directories, imports, exports, relocations, resources, TLS, load configuration,
debug records, CLR metadata, certificates, and x64 exception/unwind data.
Unavailable file-backed bytes remain unavailable.

## Disassembly and functions

Function discovery combines exports, symbols, runtime-function records, startup
metadata, direct call targets, validated thunks, and bounded executable fallbacks.
Disassembly uses exact RVA/file mappings and separates import slots from imported
function bodies.

## Control flow

RESX builds function CFGs, follows bounded direct control flow, recovers common
switch forms, records unresolved indirect edges, and reconstructs loader-visible
startup roots such as the image entry point and TLS callbacks. Traversal budgets
and incomplete edges are included in output.

## Static behavior

Behavior and contract reports correlate exact imports, local argument producers,
constants, strings, and instruction evidence. Categories include IPC, network,
crypto, executable-memory APIs, anti-debugging primitives, drivers, IOCTL/NDIS,
hypervisor instructions, and persistence-related APIs.

These are static candidates. Presence does not establish execution, success,
intent, a live peer, or security impact.

## Search and comparison

YARA-compatible rules and `find` locate bounded byte, string, constant, and
instruction evidence. Diff/index/hunt use normalized functions, CFG shape, API
sets, constants, fuzzy hashes, and metadata. Similarity scores are ranking aids,
not identity proofs.

## Explicit decoding

`payload` applies operator-selected bounded codecs or AES-CBC parameters and
records hashes for every layer. It does not infer missing keys or claim the
decoded result executed.
