import base64
import hashlib
import re
from pathlib import Path
from dnslib import DNSRecord, QTYPE

SERVER_IP = "127.0.0.1"
SERVER_PORT = 5353
ZONE = "lab"


def queryt(name: str) -> str:
    q = DNSRecord.question(name, qtype="TXT")
    pkt = q.send(SERVER_IP, SERVER_PORT, timeout=2)
    r = DNSRecord.parse(pkt)

    if r.header.rcode != 0 or len(r.rr) == 0:
        raise RuntimeError(f"NXDOMAIN/empty for {name}")

    # TXT rdata is like: "...."
    txt = str(r.rr[0].rdata)
    return txt.strip('"')


def parse_meta(meta: str) -> dict:
    # chunks=..;enc=base64;sha256=...;bytes=...
    out = {}
    for part in meta.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fetchf(name: str, out_path: Path):
    meta_txt = queryt(f"meta.{name}.{ZONE}")
    meta = parse_meta(meta_txt)

    chunk_count = int(meta["chunks"])
    expected_sha = meta.get("sha256", "")
    expected_bytes = int(meta.get("bytes", "0"))

    chunks = []
    for i in range(chunk_count):
        chunks.append(queryt(f"chunk{i}.{name}.{ZONE}"))

    data = base64.b64decode("".join(chunks).encode("ascii"))

    if expected_bytes and len(data) != expected_bytes:
        raise RuntimeError(f"size mismatch: got {len(data)} expected {expected_bytes}")

    if expected_sha and sha256_hex(data) != expected_sha:
        raise RuntimeError("sha256 mismatch (data corrupted or wrong order)")

    out_path.write_bytes(data)
    return out_path


if __name__ == "__main__":
    name = "hello"  # request "hello" -> store/hello.txt or store/hello
    out = Path(__file__).resolve().parent / f"retrieved_{name}.bin"
    p = fetchf(name, out)
    print(f"wrote: {p}")