# IOCTL device and security evidence

`resx ioctl DRIVER.sys` and `resx driver DRIVER.sys` show decoded method/access bits,
recovered input/output length guards, external/internal dispatch channels, candidate
device IDs, and code-check RVAs. `--verbose` adds dispatch roots and recovery evidence;
`--json` preserves the structured records. RIVA provides the same options.

```powershell
resx ioctl C:\Windows\System32\drivers\beep.sys --verbose
resx ioctl C:\Windows\System32\drivers\null.sys --device-security '\Device\Null'
riva ioctl C:\Windows\System32\drivers\null.sys --device-security '\\.\NUL' --json
```

Static device declarations require resolved arguments at named `IoCreateDevice`,
`IoCreateDeviceSecure`/`WdmlibIoCreateDeviceSecure`, and symbolic-link creation APIs.
Counted Unicode strings may be immutable globals or known caller locals initialized
by `RtlInitUnicodeString`. Unrelated strings, unknown initializers and malformed lengths
do not establish a name or SDDL. Each declaration includes its creation RVA and whether
the constructor's driver argument is traced to the DriverEntry object.

Device IDs on IOCTL rows are candidates sharing that recovered DRIVER_OBJECT. Several
devices can share a dispatch routine; this does not prove a per-code target, successful
creation, loaded image identity, kernel DEVICE_OBJECT address, or attached driver stack.
Dynamic PnP/KMDF device naming and registry/INF security can remain unresolved.
`FILE_DEVICE_SECURE_OPEN` describes namespace access checking, not a permissive DACL.

The optional `--device-security PATH` lookup queries one explicitly supplied local
endpoint. It resolves an object name and (where applicable) DOS alias, then queries
owner/group/DACL SDDL from an opened handle. It never loads a driver or sends an IOCTL.
Opening a device does execute its create/close path. The worker has a 15-second deadline
and 256 KiB output budget. UNC and known redirector paths are rejected.

Security evidence is separated into:

- **Declared SDDL:** constructor default; registry policy can override it.
- **Observed SDDL:** the opened endpoint's security-query result; not a direct read of
  kernel DEVICE_OBJECT memory. Audit SACL and mandatory labels are not queried.
- **Opened / open failed:** actual access probes under a non-elevated token at medium
  integrity or lower, for zero/read/write/read+write data rights.
- **DACL allows / denies:** fallback `AccessCheck` using the real linked token when
  Windows only permits identification. This does not test an open, mandatory integrity,
  or the driver's create/dispatch policy. Zero-access remains unknown in this mode.

Text output summarizes the token, SDDL and access probes without diagnostic tables.
The `User-access test token` label identifies the non-elevated access test, not
the process privileges used for the earlier SDDL lookup.
`--verbose` adds numeric errors, descriptor provenance and detailed limitations;
`--json` retains the complete evidence. Access denied does not imply elevation
will resolve it. No suitable
token, denied metadata access, unknown device associations and unsupported queries stay
unknown. An internal-device-control route is not a direct user `DeviceIoControl` route.
Even an allowed open does not prove that the driver accepts a particular IOCTL.

JSON additions: `devices`, `live_security`, and per-code `request_channels`,
`device_candidates`, `user_accessibility`. Probe `opened` and `dacl_allowed` are nullable
and distinguish observations from DACL evaluation. Static name matches do not authenticate
the currently loaded driver against the analyzed binary.
