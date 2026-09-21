import sys, struct, hashlib, mmap
MAGIC = b"APK Sig Block 42"
f = open(sys.argv[1], "rb"); m = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
# EOCD
i = m.rfind(b"PK\x05\x06")
cd_size, cd_off = struct.unpack_from("<II", m, i + 12)
# APK Signing Block sits immediately before CD
assert m[cd_off-16:cd_off] == MAGIC, "no signing block"
sb_size_end = struct.unpack_from("<Q", m, cd_off - 24)[0]
sb_start = cd_off - 8 - sb_size_end           # start of the leading size field
sb_size_start = struct.unpack_from("<Q", m, sb_start)[0]
assert sb_size_start == sb_size_end
print(f"signing block: start={sb_start} size={sb_size_end} cd_off={cd_off} cd_size={cd_size}")

# walk id-value pairs
p, end = sb_start + 8, cd_off - 24
v2 = None
while p < end:
    ln = struct.unpack_from("<Q", m, p)[0]
    bid = struct.unpack_from("<I", m, p + 8)[0]
    if bid == 0x7109871a: v2 = bytes(m[p+12 : p+8+ln])
    print(f"  pair id=0x{bid:08x} len={ln}")
    p += 8 + ln

# v2 block: len-prefixed sequence of signers
def lp(buf, o):                                  # read uint32-length-prefixed slice
    n = struct.unpack_from("<I", buf, o)[0]
    return buf[o+4:o+4+n], o+4+n
signers, _ = lp(v2, 0)
signer, _  = lp(signers, 0)
signed_data, _ = lp(signer, 0)
digests, _ = lp(signed_data, 0)
o = 0
embedded = {}
while o < len(digests):
    d, o = lp(digests, o)
    algid = struct.unpack_from("<I", d, 0)[0]
    dig, _ = lp(d, 4)
    embedded[algid] = dig
    print(f"  embedded digest alg=0x{algid:04x} -> {dig.hex()}")

# recompute per spec
def chunked(sections):
    chunks = []
    for s in sections:
        for o in range(0, len(s), 1<<20):
            chunks.append(s[o:o+(1<<20)])
    per = [hashlib.sha256(b"\xa5" + struct.pack("<I", len(c)) + c).digest() for c in chunks]
    return hashlib.sha256(b"\x5a" + struct.pack("<I", len(per)) + b"".join(per)).digest()

eocd = bytearray(m[i:])
struct.pack_into("<I", eocd, 16, sb_start)       # CD offset -> signing block offset
mine = chunked([m[0:sb_start], m[cd_off:cd_off+cd_size], bytes(eocd)])
print(f"\n  recomputed             -> {mine.hex()}")
print("\n  MATCH" if mine in embedded.values() else "\n  MISMATCH")
