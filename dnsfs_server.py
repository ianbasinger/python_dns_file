import base64
import hashlib
import os
from pathlib import Path
from dnslib import DNSRecord, DNSHeader, RR, QTYPE, TXT, RCODE
from dnslib.server import DNSServer, BaseResolver

# defaults for lab
BIND_ADDR = "127.0.0.1"
BIND_PORT = 5353
ZONE = "lab."
TTL = 60

STORE_DIR = Path(__file__).resolve().parent / "store"

# TXT strings are typically limited; this is to keep chunks well under 255 characters
CHUNK_CHARS = 180


def s_name(s: str) -> str:
    # only allow simple names for safety/clarity
    ok = "abcdefghijklmnopqrstuvwxyz0123456789-_"
    s = s.lower()
    return "".join(c for c in s if c in ok)


def f_bytes(name: str) -> bytes:
    # map <name> -> store/<name>
    # allow extensions in store files; client requests by base name
    # exact match first, otherwise try <name>.bin
    candidates = [
        STORE_DIR / name,
        STORE_DIR / f"{name}.bin",
        STORE_DIR / f"{name}.txt",
    ]
    for p in candidates:
        if p.exists() and p.is_file():
            return p.read_bytes()
    raise FileNotFoundError(name)


def b64_chunks(data: bytes) -> list[str]:
    b64 = base64.b64encode(data).decode("ascii")
    return [b64[i:i + CHUNK_CHARS] for i in range(0, len(b64), CHUNK_CHARS)]


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class dns_fs_resolver(BaseResolver):
    def resolve(self, request, handler):
        qname = str(request.q.qname).lower()
        qtype = QTYPE[request.q.qtype]

        reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=0), q=request.q)

        # only serve our zone
        if not qname.endswith(ZONE):
            reply.header.rcode = RCODE.NXDOMAIN
            return reply

        if qtype != "TXT":
            reply.header.rcode = RCODE.NXDOMAIN
            return reply

        label = qname[:-len(ZONE)].strip(".")
        if not label:
            reply.add_answer(RR(qname, QTYPE.TXT, ttl=TTL, rdata=TXT("dnsfs-lab: use meta.<name>.lab")))
            return reply

        parts = label.split(".")
        # meta.<name>.lab
        if len(parts) == 2 and parts[0] == "meta":
            name = s_name(parts[1])
            try:
                data = f_bytes(name)
            except FileNotFoundError:
                reply.header.rcode = RCODE.NXDOMAIN
                return reply

            chunks = b64_chunks(data)
            meta = f"chunks={len(chunks)};enc=base64;sha256={sha256_hex(data)};bytes={len(data)}"
            reply.add_answer(RR(qname, QTYPE.TXT, ttl=TTL, rdata=TXT(meta)))
            return reply

        # chunk<N>.<name>.lab
        if len(parts) == 2 and parts[0].startswith("chunk"):
            name = s_name(parts[1])
            try:
                idx = int(parts[0][5:])
            except ValueError:
                reply.header.rcode = RCODE.NXDOMAIN
                return reply

            try:
                data = f_bytes(name)
            except FileNotFoundError:
                reply.header.rcode = RCODE.NXDOMAIN
                return reply

            chunks = b64_chunks(data)
            if idx < 0 or idx >= len(chunks):
                reply.header.rcode = RCODE.NXDOMAIN
                return reply

            reply.add_answer(RR(qname, QTYPE.TXT, ttl=TTL, rdata=TXT(chunks[idx])))
            return reply

        reply.header.rcode = RCODE.NXDOMAIN
        return reply


if __name__ == "__main__":
    STORE_DIR.mkdir(parents=True, exist_ok=True)
    print(f"dnsfs-lab authoritative server")
    print(f"zone: {ZONE}  bind: {BIND_ADDR}:{BIND_PORT}  store: {STORE_DIR}")

    server = DNSServer(dns_fs_resolver(), address=BIND_ADDR, port=BIND_PORT)
    server.start_thread()

    input("running. press enter to stop.\n")