import base64
import gzip
import hashlib
import json
import random
import zlib
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()
root.mkdir(exist_ok=False)
rng = random.Random(20260909)
rows = []
for index in range(240):
    length = rng.randrange(0, 32768)
    if index % 3 == 0:
        raw = rng.randbytes(length)
    elif index % 3 == 1:
        pattern = rng.randbytes(rng.randrange(8, 128))
        raw = (pattern * (length // len(pattern) + 1))[:length]
    else:
        raw = json.dumps({"index": index, "endpoint": "https://fixture.invalid/local", "data": rng.choices(list(range(256)), k=length // 8)}).encode()
    codec = ["zlib", "gzip", "deflate", "base64", "hex"][index % 5]
    if codec in {"zlib", "gzip", "deflate"}:
        window = {"zlib": 15, "gzip": 31, "deflate": -15}[codec]
        compressor = zlib.compressobj(index % 10, zlib.DEFLATED, window, 8,
            [zlib.Z_DEFAULT_STRATEGY, zlib.Z_FILTERED, zlib.Z_HUFFMAN_ONLY, zlib.Z_RLE, zlib.Z_FIXED][(index // 5) % 5])
        packed = compressor.compress(raw) + compressor.flush()
    else:
        packed = base64.b64encode(raw) if codec == "base64" else raw.hex().encode()
    # Cases beyond the deliberate expansion budget are separate negative controls.
    expected = "reject-budget" if len(raw) > max(4096, min(16 * 1024 * 1024, len(packed) * 256)) else "decode"
    name = f"{index:03d}"
    (root / (name + ".encoded")).write_bytes(packed)
    (root / (name + ".expected")).write_bytes(raw)
    rows.append({"name": name, "codec": codec, "expected": expected, "encoded_sha256": hashlib.sha256(packed).hexdigest(), "output_sha256": hashlib.sha256(raw).hexdigest()})

configuration = json.dumps({"endpoint": "https://fixture.invalid/payload", "algorithm": "test-data", "enabled": True}).encode()
(root / "nested.encoded").write_bytes(base64.b64encode(gzip.compress(zlib.compress(configuration), mtime=0)))
(root / "nested.expected").write_bytes(configuration)
(root / "bomb.zlib").write_bytes(zlib.compress(b"A" * (17 * 1024 * 1024)))
(root / "manifest.json").write_text(json.dumps({"oracle": "Python stdlib zlib/gzip/base64", "zlib_version": zlib.ZLIB_VERSION, "seed": 20260909, "cases": rows}, indent=2))
print(json.dumps({"cases": len(rows), "nested_layers": 3, "root": str(root)}))
