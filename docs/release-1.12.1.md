# RESX 1.12.1

RESX 1.12.1 fixes the default output for `driver` and `ioctl`. Interactive use
now renders bounded tables for IOCTL codes, typed buffer lengths, validated NDIS
OID requests, MajorFunction assignments, and driver APIs. Full schema-versioned
JSON remains available only when `--json` is requested. Verbose text output adds
call-site arguments and evidence limits.

The x64 call recovery pass now carries Windows ABI function arguments through
validated control-flow joins, direct helper branches, MSVC stack probes, and
chained unwind fragments. It reconstructs C-like calls, bounded stack-backed
request fields, allocator-derived buffers, and symbolic size expressions such
as capped record counts. Unknown values remain explicit when the instructions
do not prove them.

On the local Blackbird J58.dll source oracle, RESX recovered all 26 compiled
`DeviceIoControl` sites and their IOCTL codes, attributed all 26 sites to named
exports, and recovered 12 proven request fields across 8 calls. The retained
comparison artifact records the source, ABI header, analyzed JSON, and unmatched
sets used for that result.
