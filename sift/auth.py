import time
from crypto_utils import derive_key, hash_password

def verify_login_timestamp(timestamp, max_skew_ns=1_000_000_000):
    now = time.time_ns()
    if abs(now - timestamp) > max_skew_ns:
        raise Exception("Timestamp too old")

def authenticate_user(username, password, users):
    user = users.get(username)
    if not user:
        raise Exception("Auth failed")

    computed_hash = hash_password(password, user["salt"])
    if computed_hash != user["hash"]:
        raise Exception("Auth failed")

def build_login_response(request_hash, server_random):
    return (request_hash + "\n" + server_random.hex()).encode()

def derive_session_key(client_random, server_random, request_hash_hex):
    return derive_key(client_random, server_random, bytes.fromhex(request_hash_hex))