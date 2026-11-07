import socket
import sys
from des_pure import ecb_encrypt

HOST = "127.0.0.1"
PORT = 5050


KEY = b"byte4eod"
DEFAULT_TRANSACTION = "masry304 | FROM: ACC-4421 | TO: ACC-9087 | AMOUNT: 250.00 EGP"


def main() -> None:
    if len(sys.argv) > 1:
        message = sys.argv[1]
    else:
        message = input("Enter transaction message (press Enter to use the default): ").strip()
        if not message:
            message = DEFAULT_TRANSACTION
    print(f"[CLIENT] Plaintext transaction: {message}")

    ciphertext = ecb_encrypt(message.encode("utf-8"), KEY)
    print(f"[CLIENT] Ciphertext ({len(ciphertext)} bytes): {ciphertext.hex()}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall(len(ciphertext).to_bytes(4, "big") + ciphertext)
        print(f"[CLIENT] Sent to {HOST}:{PORT}")


if __name__ == "__main__":
    main()
