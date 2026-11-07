from des_pure import encrypt_block

KEY = b"byte4eod"    

DEFAULT_BLOCK = "cryptos3"


def ask_block() -> bytes:
    """Ask the user for exactly 8 characters (= one 64-bit DES block)."""
    while True:
        text = input(f"Enter an 8-character block (press Enter for '{DEFAULT_BLOCK}'): ")
        text = text or DEFAULT_BLOCK
        data = text.encode("utf-8")
        if len(data) == 8:
            return data
        print(f"  '{text}' is {len(data)} bytes; a DES block must be exactly 8. Try again.")


block_a = ask_block()
block_b = block_a
last = block_a[-1]
block_c = block_a[:-1] + bytes([last + 1 if last < 126 else last - 1])

plaintext = block_a + block_b + block_c
assert len(block_a) == len(block_b) == len(block_c) == 8

blocks = [encrypt_block(plaintext[i:i + 8], KEY) for i in range(0, len(plaintext), 8)]
labels = [block_a, block_b, block_c]

for n, (pt, ct) in enumerate(zip(labels, blocks), start=1):
    print(f"Block {n}: plaintext={pt.decode(errors='replace')!r} ({pt.hex()})  ->  ciphertext={ct.hex()}")

print()
print("Block 1 == Block 2 ciphertext?", blocks[0] == blocks[1])
print("Block 1 == Block 3 ciphertext?", blocks[0] == blocks[2])
