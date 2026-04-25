# communication helper file
import socket
import struct

def send_message(sock: socket.socket, data: bytes):
    length = len(data)
    sock.sendall(struct.pack(">I", length) + data)

def recv_exact(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Connection closed")
        data += chunk
    return data

def recv_message(sock: socket.socket) -> bytes:
    raw_len = recv_exact(sock, 4)
    length = struct.unpack(">I", raw_len)[0]
    return recv_exact(sock, length)