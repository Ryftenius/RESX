# RESX JSON Output

RESX JSON output is intended for tools, tests, VS Code integration, and FFI consumers. Schemas are versioned where possible, but callers should tolerate additional fields across releases.

## General Shape

CLI commands that support `--json` usually emit either a versioned object:

```json
{
  "schema_version": 1,
  "payload": {}
}
```

or a command-specific object with stable top-level fields. New fields may be added without a schema bump when they are additive.

The DLL/FFI API wraps command output in a standard envelope:

```json
{
  "schema_version": 1,
  "api_version": 1,
  "status": "ok",
  "status_code": 0,
  "command": "peinfo",
  "args": ["sample.dll", "--json", "--no-color", "--quiet"],
  "resx_version": "1.10.0",
  "payload": {}
}
```

If command output is text, the envelope uses `text` instead of `payload`.

## Error Envelope

FFI errors use:

```json
{
  "schema_version": 1,
  "api_version": 1,
  "status": "error",
  "status_code": 5,
  "error": "message",
  "resx_version": "1.10.0"
}
```

## Address Formatting

RESX JSON generally formats RVAs and VAs as uppercase hex strings:

```json
{
  "rva": "0x00001234",
  "va": "0x0000000180001234"
}
```

Consumers should accept either strings or numeric values when reading older or internal payloads.

## PE Info

Command:

```powershell
resx peinfo <image> --json
```

Common fields:

```json
{
  "schema_version": 1,
  "image": "sample.dll",
  "arch": "x64",
  "entry_point": "0x00001000",
  "image_base": "0x0000000180000000",
  "sections": [],
  "imports": [],
  "exports": [],
  "startup_routines": [],
  "data_summary": {},
  "anomalies": []
}
```

`startup_routines` entries include:

```json
{
  "kind": "PE Entry Point",
  "source": "AddressOfEntryPoint",
  "rva": "0x00001000",
  "va": "0x0000000180001000",
  "section": ".text",
  "note": "loader transfers control here after image initialization"
}
```

Startup routines are conservative evidence. CFG chains are represented by CFG/reconstruct output, not by flooding `startup_routines`.

## Behavior

Command:

```powershell
resx behavior <image> --json
```

Common shape:

```json
{
  "schema_version": 1,
  "behavior": {
    "image": "sample.dll",
    "finding_count": 3,
    "findings": [
      {
        "category": "syscall",
        "rule": "syscall-stub-pattern",
        "severity": "high",
        "confidence": "high",
        "source": "instruction-window",
        "rva": "0x00001234",
        "detail": "direct syscall-like instruction sequence found in executable code",
        "evidence": ["0x00001234: syscall"]
      }
    ]
  }
}
```

Findings are static evidence records. `category`, `rule`, `severity`, `confidence`, `source`, and `rva` are intended for filtering; `detail` and `evidence` are human-facing context.

## Entropy

Command:

```powershell
resx entropy <image> --json
```

Common shape:

```json
{
  "schema_version": 1,
  "entropy": {
    "image": "sample.dll",
    "scope": "executable-sections",
    "window_size": 1024,
    "stride": 512,
    "summary": {
      "window_count": 12,
      "avg_entropy": 6.12,
      "min_entropy": 3.21,
      "max_entropy": 7.82,
      "high_entropy_windows": 2,
      "low_entropy_windows": 0,
      "zero_heavy_windows": 1,
      "ascii_heavy_windows": 0
    },
    "windows": []
  }
}
```

Window records include `rva`, `end_rva`, `file_offset`, `section`, `size`, `entropy`, `ascii_ratio`, `zero_ratio`, `unique_ratio`, and `flags`.

## Unpack

Command:

```powershell
resx unpack <image> --json
```

Common shape:

```json
{
  "schema_version": 1,
  "unpack": {
    "image": "sample.dll",
    "mode": "static-unpack-triage",
    "summary": "2 protector hint(s), 3 OEP candidate(s), 1 import-rebuild hint(s), 4 VM candidate(s)",
    "protector_hints": [],
    "oep_candidates": [],
    "import_rebuild_hints": [],
    "vm_candidates": [],
    "layer2": {
      "oep_windows": [],
      "import_plan": [],
      "vm_sketches": [],
      "notes": []
    },
    "next_steps": []
  }
}
```

`protector_hints` and `import_rebuild_hints` entries include `rule`, `confidence`, `detail`, and `evidence`. `oep_candidates` include `rva`, `confidence`, `reason`, and `evidence`. `vm_candidates` include `rva`, `confidence`, `kind`, `reason`, and `evidence`.

`layer2.oep_windows` entries include `rva`, `section`, `bytes_hex`, `instructions`, `control_flow`, and `data_refs`. `layer2.import_plan` entries include `dll`, `api`, `source`, `confidence`, and `evidence`. `layer2.vm_sketches` entries include `rva`, `kind`, `score`, `registers`, `mnemonics`, `instructions`, and `next_action`.

## Dump

Command:

```powershell
resx dump <image> <function> --json
```

Common payload groups:

- Target identity and resolved RVA/VA.
- Disassembly instructions.
- CFG blocks when requested.
- Reconstruction output when requested.
- API/function call map when requested.
- Strings and xrefs when requested.
- Intelli/hook evidence when requested.

Instruction-like entries usually include:

```json
{
  "rva": "0x00001234",
  "va": "0x0000000180001234",
  "bytes": "48 83 EC 28",
  "mnemonic": "sub",
  "op_str": "rsp, 28h"
}
```

## Reconstruct CFG

Command:

```powershell
resx reconstruct-cfg <image> --json
```

Common fields:

```json
{
  "schema_version": 1,
  "image": "sample.dll",
  "arch": "x64",
  "entry_point": "0x00001000",
  "stats": {},
  "roots": [],
  "notes": []
}
```

Roots contain nested function/edge data. Consumers should treat missing edge categories as empty.

## Scan

Command:

```powershell
resx scan <path> --json
```

Common fields:

```json
{
  "schema_version": 1,
  "root": "C:\\samples",
  "summary": {},
  "images": []
}
```

Image entries may include PE metadata, anomaly counts, imports/exports counts, and fuzz candidate lists.

With `--jsonl`, each line is one JSON object for one image or scan event.

## Diff, Index, and Hunt

Commands:

```powershell
resx diff <old> <new> --json
resx index <path> --db <file> --json
resx hunt <sample> --db <file> --json
```

Diff payloads include image summaries, pair summaries, function matches, unmatched functions, weak/changed matches, and optional CFG diff/graph output.

Corpus payloads include index metadata and image/function fingerprints. Fingerprints are implementation details and may grow new fields.

## Consumer Guidance

- Prefer `schema_version` and explicit keys over text parsing.
- Treat unknown fields as additive.
- Treat absent arrays as empty arrays.
- Treat absent objects as empty objects.
- Accept hex strings for addresses.
- Do not rely on array ordering unless the command describes the order as ranked or sorted.
- Keep FFI envelope handling separate from inner command payload handling.
