import time
from Crypto.Random import get_random_bytes
from crypto_utils import derive_key

LOGIN_REQ = b'\x00\x00'
LOGIN_RES = b'\x00\x10'
COMMAND_REQ = b'\x01\x00'
COMMAND_RES = b'\x01\x10'
UPLOAD_DATA = b'\x02\x00'
UPLOAD_LAST = b'\x02\x01'
UPLOAD_RESP = b'\x02\x10'
DOWNLOAD_CTRL = b'\x03\x00'
DOWNLOAD_DATA = b'\x03\x10'
DOWNLOAD_LAST = b'\x03\x11'

def build_login_payload(username, password):
    timestamp = str(time.time_ns())
    client_random = get_random_bytes(16)
    payload = (
        timestamp + "\n" +
        username + "\n" +
        password + "\n" +
        client_random.hex()
    ).encode()
    return payload, client_random

def parse_login_payload(payload: bytes):
    lines = payload.decode().split("\n")
    return int(lines[0]), lines[1], lines[2], bytes.fromhex(lines[3])

def build_command_payload(command, params):
    return (command + "\n" + "\n".join(params) if params else command).encode()

def build_download_request(filename):
    return f"dnl\n{filename}".encode()

def build_upload_request(filename, file_size, file_hash_hex):
    return f"upl\n{filename}\n{file_size}\n{file_hash_hex}".encode()

def derive_session_key(client_random, server_random, request_hash_hex):
    return derive_key(client_random, server_random, bytes.fromhex(request_hash_hex))
