# JSON schemas

RESX JSON uses a versioned outer envelope:

```json
{
  "schema_version": 1,
  "kind": "peinfo",
  "peinfo": {}
}
```

The command-specific object key matches `kind`. Current command kinds include
`peinfo`, `sections`, `pechk`, `eat`, `iat`, `dump`, `cfg`,
`reconstruct_cfg`, `behavior`, `contracts`, `ipc`, `network`,
`crypto`, `strings`, `entropy`, `payload`, `scan`, `diff`, `index`,
`hunt`, and `find`.

## Stability rules

- A field retains its established representation. Numeric coordinates remain
  numeric; formatted coordinates use `0x`-prefixed strings.
- Missing evidence is null, absent, or explicitly unavailable. It is not replaced
  with zero.
- Reports that hit a bound expose the applicable limit and truncation state.
- Findings preserve evidence location, confidence, and interpretation where
  applicable.
- New optional fields may be added within a schema version. Breaking changes
  require a new version.

Use `--json` for one document and `--jsonl` for streaming corpus commands.
Diagnostics remain on stderr and are not mixed into the JSON document.

## Dump reports

The `dump` object includes `signature` and `decode_conflicts`. Signature reports
identify their source, inferred parameters, completeness, and traversal limits.
Conflict reports retain bounded overlapping-decode evidence without assigning
intent. Instruction coordinates (`block_start`, `rva`, `va`, and optional
`rebased_va`) are formatted hexadecimal strings; opcode bytes are lowercase hex.

## PE triage

`peinfo` may include a bounded `triage` array. Each item separates observed
evidence from interpretation and includes severity, confidence, and kind.

## PE validation

`pechk <image> --json` emits the dedicated `pechk` object. It contains PE identity,
header status, and at most 256 validation findings. `finding_count`, `report_limit`,
and `report_truncated` make the bound explicit. The command does not run or emit
function discovery, CFG, string, or indirect-flow analysis.
