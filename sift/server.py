import socket
import time
import hashlib
import os

from common import send_message, recv_message
from mtp import MTP
from crypto_utils import load_private_key, rsa_decrypt, derive_key
from Crypto.Random import get_random_bytes
from commands import CommandHandler
from crypto_utils import hash_password
from auth import verify_login_timestamp, authenticate_user, build_login_response, derive_session_key
from protocol import parse_login_payload, LOGIN_RES, COMMAND_RES, UPLOAD_DATA, UPLOAD_LAST, UPLOAD_RESP, DOWNLOAD_CTRL, DOWNLOAD_DATA, DOWNLOAD_LAST

HOST = "0.0.0.0"
PORT = 5150

USERS = {
    "alice": {
        "salt": b"static_salt_123",
        "hash": hash_password("aaa", b"static_salt_123")
    }
}
FRAGMENT_SIZE = 1024

def handle_client(conn, addr):
    print(f"[+] Client connected: {addr}")

    try:
        raw = recv_message(conn)
        encrypted_part = raw[:-256]
        etk = raw[-256:]
        privkey = load_private_key("srvkey.pem")
        tk = rsa_decrypt(privkey, etk)
        mtp = MTP(tk)
        typ, payload = mtp.decrypt(encrypted_part)
        
        timestamp, username, password, client_random = parse_login_payload(payload)
        
        verify_login_timestamp(timestamp)
        authenticate_user(username, password, USERS)

        request_hash = hashlib.sha256(payload).hexdigest()
        server_random = get_random_bytes(16)

        send_message(conn, mtp.encrypt(
            b'\x00\x10',
            build_login_response(request_hash, server_random)
        ))

        session_key = derive_session_key(client_random, server_random, request_hash)
        #session_key = derive_key(client_random, server_random, request_hash)

        mtp.key = session_key
        handler = CommandHandler("server_files")

        while True:
            raw = recv_message(conn)
            typ, payload = mtp.decrypt(raw)
            parts = payload.decode().split("\n")
            cmd = parts[0]
            req_hash = hashlib.sha256(payload).hexdigest()

            # DOWNLOAD
            if cmd == "dnl":
                #inside the command handler because of pwd/lst command
                if len(parts) < 2:
                    resp = [cmd, req_hash, "reject", "Missing parameter"]
                    send_message(conn, mtp.encrypt(b'\x01\x10', "\n".join(resp).encode()))
                    continue
                filename = parts[1]
                path = handler._safe_path(filename)

                if not os.path.exists(path):
                    send_message(conn, mtp.encrypt(
                        b'\x01\x10',
                        f"dnl\n{req_hash}\nreject\nFile not found".encode()
                    ))
                    continue

                with open(path, "rb") as f:
                    data = f.read()

                h = hashlib.sha256(data).hexdigest()

                send_message(conn, mtp.encrypt(
                    b'\x01\x10',
                    f"dnl\n{req_hash}\naccept\n{len(data)}\n{h}".encode()
                ))

                raw = recv_message(conn)
                typ, payload = mtp.decrypt(raw)

                if payload == b"cancel":
                    continue
                if payload != b"ready":
                    raise Exception("Invalid download response")

                for i in range(0, len(data), FRAGMENT_SIZE):
                    chunk = data[i:i+FRAGMENT_SIZE]
                    t = DOWNLOAD_LAST if i + FRAGMENT_SIZE >= len(data) else DOWNLOAD_DATA
                    send_message(conn, mtp.encrypt(t, chunk))

                continue

            # UPLOAD
            if cmd == "upl":
                #inside the command handler because of pwd/lst command
                if len(parts) < 4:
                    resp = [cmd, req_hash, "reject", "Missing parameter"]
                    send_message(conn, mtp.encrypt(COMMAND_RES, "\n".join(resp).encode()))
                    continue
                filename = parts[1]
                size = int(parts[2])
                expected_hash = parts[3]

                path = handler._safe_path(filename)

                send_message(conn, mtp.encrypt(
                    COMMAND_RES,
                    f"upl\n{req_hash}\naccept".encode()
                ))

                received = b""

                while True:
                    raw = recv_message(conn)
                    typ, chunk = mtp.decrypt(raw)

                    received += chunk

                    if typ == UPLOAD_LAST:
                        break

                with open(path, "wb") as f:
                    f.write(received)

                h = hashlib.sha256(received).hexdigest()

                send_message(conn, mtp.encrypt(
                    UPLOAD_RESP,
                    f"{h}\n{len(received)}".encode()
                ))

                continue

            # COMMANDS
            try:
                if cmd == "pwd":
                    res = handler.pwd()
                    resp = ["pwd", req_hash, "success", res]

                elif cmd == "lst":
                    res = handler.lst()
                    resp = ["lst", req_hash, "success", res]

                
                elif cmd == "chd":
                    if len(parts) < 2:
                        resp = [cmd, req_hash, "failure", "Missing parameter"]
                        send_message(conn, mtp.encrypt(COMMAND_RES, "\n".join(resp).encode()))
                        continue
                    else:
                        handler.chd(parts[1])
                        resp = ["chd", req_hash, "success"]

                elif cmd == "mkd":
                    if len(parts) < 2:
                        resp = [cmd, req_hash, "failure", "Missing parameter"]
                        send_message(conn, mtp.encrypt(COMMAND_RES, "\n".join(resp).encode()))
                        continue
                    else:   
                        handler.mkd(parts[1])
                        resp = ["mkd", req_hash, "success"]

                elif cmd == "del":
                    if len(parts) < 2:
                        resp = [cmd, req_hash, "failure", "Missing parameter"]
                        send_message(conn, mtp.encrypt(COMMAND_RES, "\n".join(resp).encode()))
                        continue
                    else:
                        handler.delete(parts[1])
                        resp = ["del", req_hash, "success"]

                else:
                    resp = [cmd, req_hash, "failure", "Unknown command"]

            except Exception as e:
                resp = [cmd, req_hash, "failure", str(e)]

            send_message(conn, mtp.encrypt(
                COMMAND_RES,
                "\n".join(resp).encode()
            ))

    except Exception as e:
        print("[!] Error:", e)
        conn.close()
        return
    finally:
        conn.close()

def start_server():
    os.makedirs("server_files", exist_ok=True)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print("[+] Listening...")

        while True:
            conn, addr = s.accept()
            handle_client(conn, addr)

if __name__ == "__main__":
    start_server()