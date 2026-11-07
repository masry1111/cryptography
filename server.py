import socket
from des_pure import ecb_decrypt

HOST = "127.0.0.1"
PORT = 5050
KEY = b"byte4eod"


def recv_exact(conn: socket.socket, n: int) -> bytes:
    """Read exactly n bytes from the socket (TCP is a stream, not messages)."""
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Connection closed before full message arrived")
        data += chunk
    return data


def main() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, PORT))
        srv.listen(1)
        print(f"[SERVER] Listening on {HOST}:{PORT} ...")

        conn, addr = srv.accept()
        with conn:
            print(f"[SERVER] Connection from {addr[0]}:{addr[1]}")

            length = int.from_bytes(recv_exact(conn, 4), "big")
            ciphertext = recv_exact(conn, length)
            print(f"[SERVER] Received ciphertext ({length} bytes): {ciphertext.hex()}")

            plaintext = ecb_decrypt(ciphertext, KEY)
            print(f"[SERVER] Decrypted transaction: {plaintext.decode('utf-8')}")


if __name__ == "__main__":
    main()
