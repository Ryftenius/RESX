"""Static command/offset/budget regression matrix, with observed process resource use.
Usage: python validate-contract-matrix.py <resx.exe> <new-output-dir> <image> [...]
Inputs are never loaded or executed. Endpoint strings are never contacted.
"""
import ctypes
from ctypes import wintypes
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

class MemoryCounters(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("faults", wintypes.DWORD)] + [
        (name, ctypes.c_size_t) for name in ("peak", "working", "paged_peak", "paged", "nonpaged_peak", "nonpaged", "pagefile", "pagefile_peak")]

get_memory = ctypes.WinDLL("psapi").GetProcessMemoryInfo
get_memory.argtypes = [wintypes.HANDLE, ctypes.POINTER(MemoryCounters), wintypes.DWORD]
get_memory.restype = wintypes.BOOL
tool = Path(sys.argv[1]).resolve()
out = Path(sys.argv[2]).resolve()
out.mkdir()
rows = []
try:
    for index, path in enumerate(map(Path, sys.argv[3:])):
        path = path.resolve()
        raw = path.read_bytes()
        before = hashlib.sha256(raw).hexdigest()
        for command in ["contracts", "network", "strings"]:
            name = f"{index:02d}-{path.name}-{command}"
            argv = [str(tool), command, str(path), "--json", "--quiet", "--no-pdb", "--no-color"]
            begin = time.monotonic()
            peak = 0
            with (out/(name+".json")).open("wb") as stdout, (out/(name+".stderr.txt")).open("wb") as stderr:
                process = subprocess.Popen(argv, stdout=stdout, stderr=stderr)
                while True:
                    counters = MemoryCounters()
                    counters.cb = ctypes.sizeof(counters)
                    if get_memory(int(process._handle), ctypes.byref(counters), counters.cb):
                        peak = max(peak, counters.peak)
                    code = process.poll()
                    if code is not None: break
                    if time.monotonic()-begin > 45:
                        process.kill(); process.wait()
                        raise AssertionError(f"{name}: exceeded 45 seconds")
                    # Bounded performance sampling only, not production telemetry.
                    time.sleep(0.025)
            row = {"image": str(path), "image_sha256": before, "argv": argv,
                   "pid": process.pid, "exit_code": code, "wall_seconds": time.monotonic()-begin,
                   "observed_peak_working_set_bytes": peak or None}
            rows.append(row)
            assert code == 0, (name, (out/(name+".stderr.txt")).read_text())
            document = json.loads((out/(name+".json")).read_bytes())
            assert document["schema_version"] == 1
            body = document[command]
            if command == "strings":
                findings = body["strings"]
                assert len(findings) <= 8192
                for finding in findings:
                    offset = int(finding["file_offset"], 0)
                    value = finding["value"]
                    encoding = "utf-16le" if finding["encoding"] == "utf16le" else "ascii"
                    encoded = value.encode(encoding)
                    assert raw[offset:offset+len(encoded)] == encoded
                row["checks"] = "Every emitted string maps exactly to input bytes; count budget enforced"
            else:
                assert body["image_sha256"] == before
                assert body["decoded_instructions"] <= 65536 and len(body["calls"]) <= 1024
                assert body["evidence_status"] == "static; no target execution"
                sites = {c["site_rva"] for c in body["calls"]}
                for collection in ["network_requests", "crypto_configurations"]:
                    for flow in body["flows"][collection]:
                        assert set(flow["depends_on"]) <= sites
                row["checks"] = "Schema, bounded counts, input hash and producer references; no real-image semantic accuracy claim"
            assert hashlib.sha256(path.read_bytes()).hexdigest() == before
            row["status"] = "passed"
            print(name, "passed", flush=True)
finally:
    (out/"manifest.json").write_text(json.dumps({"utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "tool": str(tool), "tool_sha256": hashlib.sha256(tool.read_bytes()).hexdigest(), "runs": rows,
        "memory_note": "Windows process peak working set sampled every 25 ms while alive; short-lived final peaks may be missed"}, indent=2))
