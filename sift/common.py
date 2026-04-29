# communication helper file
import socket
import struct

def send_message(sock: socket.socket, data: bytes):
    sock.sendall(data)
    print(f"[COMMON SEND] len={len(data)}")

def recv_exact(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Connection closed")
        data += chunk
    return data

def recv_message(sock: socket.socket) -> bytes:
    header = recv_exact(sock, 16)
    if len(header) < 16:
        raise ConnectionError("Incomplete header")
    length = struct.unpack(">H", header[4:6])[0]
    if length < 16:
        raise ValueError("Invalid message length")
    body = recv_exact(sock, length - 16)
    print(f"[COMMON RECV] header={header.hex()} length={length}")
    return header + body