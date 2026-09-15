"""Read-only PE analysis checks against an independent byte-level oracle.

Uses only Python's standard library. Does not load/execute input images, query
signer trust, retrieve symbols, or claim runtime mitigation enforcement.
"""
import argparse
import collections
import datetime
import hashlib
import json
import math
import pathlib
import platform
import struct
import subprocess
import time


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def headers(path):
    raw = path.read_bytes()
    pe = struct.unpack_from("<I", raw, 0x3C)[0]
    assert raw[:2] == b"MZ" and raw[pe:pe + 4] == b"PE\0\0"
    count = struct.unpack_from("<H", raw, pe + 6)[0]
    opt_size = struct.unpack_from("<H", raw, pe + 20)[0]
    opt = pe + 24
    magic = struct.unpack_from("<H", raw, opt)[0]
    assert magic in (0x10B, 0x20B)
    image_base = struct.unpack_from("<Q" if magic == 0x20B else "<I", raw, opt + (24 if magic == 0x20B else 28))[0]
    fields = {"image_base": image_base}
    for name, offset, kind in [("entry_point", 16, "I"), ("section_alignment", 32, "I"),
                               ("file_alignment", 36, "I"), ("size_of_image", 56, "I"),
                               ("size_of_headers", 60, "I"), ("checksum", 64, "I"),
                               ("subsystem", 68, "H"), ("dll_characteristics", 70, "H")]:
        fields[name] = struct.unpack_from("<" + kind, raw, opt + offset)[0]
    sections = []
    for index in range(count):
        pos = opt + opt_size + index * 40
        name = raw[pos:pos + 8].split(b"\0")[0].decode("ascii")
        virtual_size, rva, raw_size, raw_offset = struct.unpack_from("<IIII", raw, pos + 8)
        flags = struct.unpack_from("<I", raw, pos + 36)[0]
        data = raw[raw_offset:raw_offset + raw_size]
        entropy = -sum((n / len(data)) * math.log2(n / len(data)) for n in collections.Counter(data).values()) if data else 0
        sections.append(dict(name=name, virtual_size=virtual_size, rva=rva, raw_size=raw_size,
                             raw_offset=raw_offset, entropy=entropy,
                             protections="".join(c for c, bit in [("R", 0x40000000), ("W", 0x80000000), ("X", 0x20000000)] if flags & bit) or "-"))
    return fields, sections


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--resx", type=pathlib.Path, required=True)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    parser.add_argument("images", type=pathlib.Path, nargs="+")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    manifest = dict(started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    host=platform.node(), platform=platform.platform(), python=platform.python_version(),
                    resx=str(args.resx.resolve()), resx_sha256=digest(args.resx), runs=[])
    failures = []
    for index, path in enumerate(args.images):
        path = path.resolve()
        expected_fields, expected_sections = headers(path)
        before_hash = digest(path)
        for command in ("sections", "eat", "iat", "entropy"):
            argv = [str(args.resx.resolve()), command, str(path), "--json", "--quiet", "--no-color", "--no-pdb"]
            prefix = f"{index:02d}-{path.name}-{command}"
            started = time.monotonic()
            run = dict(argv=argv, image_sha256=before_hash,
                       started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
            try:
                result = subprocess.run(argv, capture_output=True, timeout=45)
                run.update(exit_code=result.returncode, seconds=time.monotonic() - started)
                (args.out / (prefix + ".json")).write_bytes(result.stdout)
                (args.out / (prefix + ".stderr.txt")).write_bytes(result.stderr)
                assert result.returncode == 0, f"exit {result.returncode}"
                actual = json.loads(result.stdout)
                assert actual["schema_version"] == 1
                if command == "sections":
                    actual = actual["dump"]
                    for key, expected in expected_fields.items():
                        assert int(actual[key], 0) == expected, (key, actual[key], expected)
                    assert len(actual["sections"]) == len(expected_sections)
                    for observed, expected in zip(actual["sections"], expected_sections):
                        for key, value in expected.items():
                            if key == "entropy":
                                assert abs(observed[key] - value) < 0.00001, (key, observed[key], value)
                            elif isinstance(value, int):
                                assert int(observed[key], 0) == value, (key, observed[key], value)
                            else:
                                assert observed[key] == value, (key, observed[key], value)
                    run["checks"] = "headers, section layout, permission flags, independent Shannon entropy"
                else:
                    run["checks"] = "successful command and JSON envelope only; semantic accuracy not established"
                run["status"] = "passed"
            except (AssertionError, KeyError, ValueError, subprocess.TimeoutExpired) as error:
                run.update(status="failed", error=str(error), seconds=time.monotonic() - started)
                failures.append(prefix)
            manifest["runs"].append(run)
            print(prefix, run["status"], flush=True)
        assert digest(path) == before_hash, f"input changed during validation: {path}"
    manifest["failures"] = failures
    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return bool(failures)


if __name__ == "__main__":
    raise SystemExit(main())
