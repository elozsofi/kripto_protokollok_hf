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
        length = 16 + len(payload) + 12 + 256
        header = self._build_header(typ, length, sqn, rnd)
        cipher.update(header)
        ciphertext, tag = cipher.encrypt_and_digest(payload)
        if typ == b'\x00\x00':
            # header = self._build_header(typ, length, sqn, rnd)
            message = header + ciphertext + tag
            print(f"[MTP ENCRYPT] typ={typ.hex()} length={length} sqn={sqn} rnd={rnd.hex()} header={header.hex()} payload_len={len(payload)} ciphertext_len={len(ciphertext)} tag={tag.hex()} message_len={len(message)}")
            self.send_sqn += 1
            return message
        else:
            length = 16 + len(ciphertext) + 12
            header = self._build_header(typ, length, sqn, rnd)
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce, mac_len=12)
            cipher.update(header)
            ciphertext, tag = cipher.encrypt_and_digest(payload)
            message = header + ciphertext + tag
            print(f"[MTP ENCRYPT] typ={typ.hex()} length={length} sqn={sqn} rnd={rnd.hex()} header={header.hex()} payload_len={len(payload)} ciphertext_len={len(ciphertext)} tag={tag.hex()} message_len={len(message)}")
            self.send_sqn += 1
            return message

    def decrypt(self, message: bytes):
        if len(message) < 28:
            raise ValueError("Message too short")

        header = message[:16]
        typ = header[2:4]
        tag = message[-12:]
        ciphertext = message[16:-12]
        ver = header[:2]
        length = struct.unpack(">H", header[4:6])[0]
        sqn = struct.unpack(">H", header[6:8])[0]
        rnd = header[8:14]

        print(f"[MTP DECRYPT] raw_len={len(message)} typ={typ.hex()} ver={ver.hex()} length={length} sqn={sqn} rnd={rnd.hex()} header={header.hex()} ciphertext_len={len(ciphertext)} tag_len={len(tag)}")

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

        print(f"[MTP DECRYPT] payload_len={len(payload)}")
        return typ, payload