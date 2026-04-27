import socket
import time
import hashlib
import os

from common import send_message, recv_message
from mtp import MTP
from crypto_utils import load_public_key, rsa_encrypt, derive_key
from Crypto.Random import get_random_bytes
from files import split_file, compute_file_hash
from protocol import (
    LOGIN_REQ,
    COMMAND_REQ,
    UPLOAD_DATA,
    UPLOAD_LAST,
    DOWNLOAD_DATA,
    DOWNLOAD_LAST,
    DOWNLOAD_CTRL,
    build_login_payload,
    build_command_payload,
    build_download_request,
    build_upload_request,
    derive_session_key
    )

HOST = "127.0.0.1"
PORT = 5150

USERNAME = "alice"
PASSWORD = "aaa"

def start_client():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print("[+] Connected")

        #necessary if the teachers server is used, otherwise the public key of the local server can be used
        #pubkey = load_public_key("teacher_srvpubkey.pem") 
        pubkey = load_public_key("srvpubkey.pem")

        tk = get_random_bytes(32)
        mtp = MTP(tk)

        payload, client_random = build_login_payload(USERNAME, PASSWORD)

        encrypted_payload = mtp.encrypt(LOGIN_REQ, payload)
        etk = rsa_encrypt(pubkey, tk)

        send_message(s, encrypted_payload + etk)

        request_hash = hashlib.sha256(payload).hexdigest()

        raw = recv_message(s)
        typ, response_payload = mtp.decrypt(raw)

        lines = response_payload.decode().split("\n")
        received_hash = lines[0]
        server_random = bytes.fromhex(lines[1])

        if received_hash != request_hash:
            raise Exception("Login hash mismatch")

        session_key = derive_session_key(client_random, server_random, request_hash)
        #session_key = derive_key(client_random, server_random, request_hash)
        mtp.key = session_key

        print("[+] Login successful")

        while True:
            cmd_input = input(">>> ").strip()
            if not cmd_input:
                continue

            parts = cmd_input.split()
            command = parts[0]
            params = parts[1:]

            # --- DOWNLOAD ---
            if command == "dnl":
                if len(params) < 1:
                    print("[ERROR] Missing filename")
                    continue
                filename = params[0]

                payload = build_download_request(filename)
                req_hash = hashlib.sha256(payload).hexdigest()

                send_message(s, mtp.encrypt(COMMAND_REQ, payload))

                raw = recv_message(s)
                typ, res_payload = mtp.decrypt(raw)
                parts = res_payload.decode().split("\n")

                if parts[2] != "accept":
                    print("[ERROR]", parts[3])
                    continue

                size = int(parts[3])
                expected_hash = parts[4]

                print(f"[+] Downloading {filename} ({size} bytes)")
                if size > 10_000_000:
                    send_message(s, mtp.encrypt(DOWNLOAD_CTRL, b"cancel"))
                    print("[!] Download cancelled (too large)")
                    continue

                send_message(s, mtp.encrypt(DOWNLOAD_CTRL, b"ready"))
                received = b""

                while True:
                    raw = recv_message(s)
                    typ, chunk = mtp.decrypt(raw)

                    received += chunk

                    if typ == DOWNLOAD_LAST:
                        break

                with open(filename, "wb") as f:
                    f.write(received)

                h = hashlib.sha256(received).hexdigest()

                if h != expected_hash:
                    print("[ERROR] Hash mismatch")
                else:
                    print("[+] Download OK")

                continue

            # --- UPLOAD ---
            if command == "upl":
                if len(params) < 1:
                    print("[ERROR] Missing filename")
                    continue
                filename = params[0]

                if not os.path.exists(filename):
                    print("[ERROR] File not found")
                    continue

                file_hash, file_size = compute_file_hash(filename)

                payload = build_upload_request(filename, file_size, file_hash.hex())
                req_hash = hashlib.sha256(payload).hexdigest()

                send_message(s, mtp.encrypt(COMMAND_REQ, payload))

                raw = recv_message(s)
                typ, res_payload = mtp.decrypt(raw)
                parts = res_payload.decode().split("\n")

                if parts[2] != "accept":
                    print("[ERROR]", parts[3])
                    continue

                print("[+] Upload started")

                chunks = list(split_file(filename))

                for i, chunk in enumerate(chunks):
                    t = UPLOAD_LAST if i == len(chunks) - 1 else UPLOAD_DATA
                    send_message(s, mtp.encrypt(t, chunk))

                raw = recv_message(s)
                typ, res_payload = mtp.decrypt(raw)

                h, size = res_payload.decode().split("\n")

                if h != file_hash.hex():
                    print("[ERROR] Hash mismatch")
                else:
                    print("[+] Upload OK")

                continue

            payload = build_command_payload(command, params)
            req_hash = hashlib.sha256(payload).hexdigest()

            send_message(s, mtp.encrypt(COMMAND_REQ, payload))

            raw = recv_message(s)
            typ, res_payload = mtp.decrypt(raw)

            parts = res_payload.decode().split("\n")

            if parts[1] != req_hash:
                print("[!] Hash mismatch")
                break

            if parts[2] == "success":
                print(parts[3] if len(parts) > 3 else "OK")
            else:
                print("[ERROR]", parts[3])


if __name__ == "__main__":
    start_client()