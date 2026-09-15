# RESX 1.14.0

RESX 1.14.0 adds correlated SLAT hook-machinery recovery to `driver`.

Intel EPT recovery requires all of the following static evidence before the
capability is reported:

- VMCS reads of guest physical address (`0x2400`) and exit qualification
  (`0x6400`) in one violation handler
- decoding of read, write, and execute access state from the qualification
- both read and write access to the VMCS EPT pointer (`0x201A`), establishing
  dynamic root selection rather than one-time EPT setup
- an `INVEPT` invalidation site

AMD NPT recovery requires a VMCB nested-paging setup with `NpEnable`, ASID, and
`NCr3`, a `VMRUN` site, and a separate NPF path that reads adjacent `ExitInfo1`
and `ExitInfo2` state, decodes write and execute faults, aligns the GPA, and
accesses the matching `NCr3` field for dynamic root selection.

The text capability report and JSON evidence contain the RVA, owning recovered
function, and instruction for every part of each correlation. Static evidence
establishes that the binary contains SLAT interception and remapping machinery;
whether a target was configured and whether a hook became active remain runtime
questions.

The redundant driver and hypervisor confidence rows were removed from the text
summary. Evidence-specific qualification remains available in the detailed
report and JSON output.
