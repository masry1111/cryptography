from des_pure import encrypt_block

IP = [58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,
      62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
      57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,
      61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7]
FP = [40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,
      38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,
      36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,
      34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25]
E = [32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,
     16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1]
P = [16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,
     2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25]
PC1 = [57,49,41,33,25,17,9,1,58,50,42,34,26,18,
       10,2,59,51,43,35,27,19,11,3,60,52,44,36,
       63,55,47,39,31,23,15,7,62,54,46,38,30,22,
       14,6,61,53,45,37,29,21,13,5,28,20,12,4]
PC2 = [14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,
       26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,
       51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32]
SHIFTS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]
SBOX = [
 [[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],[0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
  [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],[15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]],
 [[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],[3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
  [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],[13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]],
 [[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],[13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
  [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],[1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]],
 [[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],[13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
  [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],[3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]],
 [[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],[14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
  [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],[11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]],
 [[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],[10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
  [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],[4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]],
 [[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],[13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
  [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],[6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]],
 [[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],[1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
  [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],[2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]],
]


def bits(data: bytes) -> str:
    return "".join(f"{b:08b}" for b in data)


def permute(s: str, table) -> str:
    return "".join(s[i - 1] for i in table)


def grp(s: str, n: int) -> str:
    return " ".join(s[i:i + n] for i in range(0, len(s), n))


def xor(a: str, b: str) -> str:
    return "".join("1" if x != y else "0" for x, y in zip(a, b))


def key_schedule(key: bytes):
    k56 = permute(bits(key), PC1)
    c, d = k56[:28], k56[28:]
    subkeys, cds = [], []
    for sh in SHIFTS:
        c, d = c[sh:] + c[:sh], d[sh:] + d[:sh]
        cds.append((c, d))
        subkeys.append(permute(c + d, PC2))
    return k56, subkeys, cds


def feistel(r: str, k: str, verbose=False):
    er = permute(r, E)
    x = xor(er, k)
    out = ""
    log = []
    for i in range(8):
        six = x[6 * i: 6 * i + 6]
        row = int(six[0] + six[5], 2)
        col = int(six[1:5], 2)
        val = SBOX[i][row][col]
        out += f"{val:04b}"
        log.append((i + 1, six, six[0] + six[5], row, six[1:5], col, val, f"{val:04b}"))
    return er, x, log, out, permute(out, P)


def des_encrypt_block(block: bytes, key: bytes) -> bytes:
    _, subkeys, _ = key_schedule(key)
    ip = permute(bits(block), IP)
    l, r = ip[:32], ip[32:]
    for k in subkeys:
        _, _, _, _, f = feistel(r, k)
        l, r = r, xor(l, f)
    return int(permute(r + l, FP), 2).to_bytes(8, "big")


if __name__ == "__main__":
    KEY = b"byte4eod" 

    while True:
        text = input("Enter an 8-character plaintext block (press Enter for 'masry304'): ") or "masry304"
        PT = text.encode("utf-8")
        if len(PT) == 8:
            break
        print(f"  '{text}' is {len(PT)} bytes; a DES block must be exactly 8. Try again.")

    print(f"Plaintext : {PT!r}  hex={PT.hex()}")
    print(f"Key       : {KEY!r}  hex={KEY.hex()}\n")
    print("Plaintext bits :", grp(bits(PT), 8))
    print("Key bits       :", grp(bits(KEY), 8), "\n")

    ip = permute(bits(PT), IP)
    l0, r0 = ip[:32], ip[32:]
    print("After IP       :", grp(ip, 8))
    print("L0             :", grp(l0, 4))
    print("R0             :", grp(r0, 4), "\n")

    k56, subkeys, cds = key_schedule(KEY)
    print("PC-1 (56 bits) :", grp(k56, 7))
    print("C0             :", grp(k56[:28], 4))
    print("D0             :", grp(k56[28:], 4))
    print("C1 (shift 1)   :", grp(cds[0][0], 4))
    print("D1 (shift 1)   :", grp(cds[0][1], 4))
    print("K1 (48 bits)   :", grp(subkeys[0], 6), "\n")

    er, x, log, sout, f = feistel(r0, subkeys[0])
    print("R0 (32)        :", grp(r0, 4))
    print("E(R0) (48)     :", grp(er, 6))
    print("K1 (48)        :", grp(subkeys[0], 6))
    print("E(R0) xor K1   :", grp(x, 6), "\n")
    print("S-box lookups  (row = outer bits b1b6, col = inner bits b2b3b4b5):")
    for n, six, rb, row, cb, col, val, vb in log:
        print(f"  S{n}: in={six}  row={rb}={row}  col={cb}={col}  -> {val:2d} = {vb}")
    print("\nS-box output (32) :", grp(sout, 4))
    print("P(S-out) = f(R0,K1):", grp(f, 4), "\n")

    l1 = r0
    r1 = xor(l0, f)
    print("L1 = R0            :", grp(l1, 4))
    print("R1 = L0 xor f      :", grp(r1, 4))
    print(f"L1 hex = {int(l1, 2):08x}   R1 hex = {int(r1, 2):08x}\n")

    mine = des_encrypt_block(PT, KEY)
    ref = encrypt_block(PT, KEY)
    print("Full 16-round DES (this script) :", mine.hex())
    print("des_pure.py encrypt_block       :", ref.hex())
    print("MATCH:", mine == ref)
    std = encrypt_block(bytes.fromhex("0123456789ABCDEF"), bytes.fromhex("133457799BBCDFF1"))
    print("Standard test vector            :", std.hex(), "(expected 85e813540f0ab405)")
