# CLI behavior

RESX uses:

```text
resx <command> [arguments] [options]
```

Run `resx help` for grouped commands, `resx help all` for every generated
flag, and `resx help <command>` for examples.

## Output modes

Normal output presents conclusions and important limitations. `--verbose` adds
bounded evidence, function-boundary rationale, traversal limits, and representative
disassembly. `--diagnostic` implies verbose output and adds structured developer
events. `--diagnostic-trace` increases the developer event level to TRACE.

Diagnostics go to stderr. Analysis output retains its selected text, JSON, or
JSONL format on stdout or `--out`.

Color is enabled for an interactive terminal and disabled for redirected output
unless explicitly requested. Addresses, opcode bytes, mnemonics, operands,
selected instructions, warnings, errors, success markers, and confidence labels
use distinct semantic styles.

## Address forms

- `rva:0x1234`
- `va:0x180001234`
- `file:0x400`
- `--ordinal 12`
- `module.dll!Export`

Bare hexadecimal values are interpreted according to the selected command and
reported coordinate system. Use explicit prefixes in automation.

## Input resolution

Explicit paths take precedence. Name lookup can search the current directory,
operator-provided `--path` directories, configured priority directories, PATH,
and applicable Windows system directories. `--no-cwd`, `--no-path`, and
`--no-system` disable those sources.

## Bounds and partial results

Every parser and analysis traversal has explicit limits. When a report is
truncated, it includes the relevant limit and does not present the result as a
complete image-wide conclusion.
# String evidence controls

`resx strings <image>` defaults to 200 results and filters low-quality UTF-16
binary coincidences. Use `--strings-encoding ascii|utf16le|both`,
`--strings-min-len <n>`, `--strings-limit <n>`, `--strings-match <text>`,
`--strings-tag <tag>`, or `--strings-interesting` to narrow evidence.
`--strings-raw-wide` restores permissive UTF-16 candidates. Values such as
`TARGET_OK` are tagged `success-marker`; only brace-form tokens are tagged
`flag-candidate`.
