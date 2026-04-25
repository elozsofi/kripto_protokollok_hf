import os
import struct
from Crypto.Cipher import AES

VERSION = b'\x01\x00'

class MTP:
    def __init__(self, key: bytes):
        self.key = key
        self.send_sqn = 1
        self.recv_sqn = 0

    def _build_header(self, typ: bytes, length: int, sqn: int, rnd: bytes):
        return (
            VERSION +
            typ +
            struct.pack(">H", length) +
            struct.pack(">H", sqn) +
            rnd +
            b'\x00\x00'
        )

    def encrypt(self, typ: bytes, payload: bytes) -> bytes:
        rnd = os.urandom(6)
        sqn = self.send_sqn
        nonce = struct.pack(">H", sqn) + rnd
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce, mac_len=12)
        header = self._build_header(typ, 0, sqn, rnd)
        cipher.update(header)
        ciphertext, tag = cipher.encrypt_and_digest(payload)
        length = 16 + len(ciphertext) + 12
        header = self._build_header(typ, length, sqn, rnd)
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce, mac_len=12)
        cipher.update(header)
        ciphertext, tag = cipher.encrypt_and_digest(payload)
        self.send_sqn += 1
        return header + ciphertext + tag

    def decrypt(self, message: bytes):
        if len(message) < 28:
            raise ValueError("Message too short")

        header = message[:16]
        tag = message[-12:]
        ciphertext = message[16:-12]
        ver = header[:2]
        typ = header[2:4]
        length = struct.unpack(">H", header[4:6])[0]
        sqn = struct.unpack(">H", header[6:8])[0]
        rnd = header[8:14]

        if ver != VERSION:
            raise ValueError("Invalid version")

        if length != len(message):
            raise ValueError("Invalid length")

        if sqn <= self.recv_sqn:
            raise ValueError("Replay attack detected")

        nonce = struct.pack(">H", sqn) + rnd
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce, mac_len=12)
        cipher.update(header)
        payload = cipher.decrypt_and_verify(ciphertext, tag)
        self.recv_sqn = sqn

        return typ, payload