"""
XDES-A Cipher Implementation
Argon2id KDF → Independent round keys → 128-bit block (dual 64-bit Feistel)
Pre/Post Whitening (DES-X) → CTR Mode → HMAC-SHA256 (Encrypt-then-MAC)
"""

import os
import hmac
import hashlib
import struct
from argon2.low_level import hash_secret_raw, Type

# ─────────────────────────────────────────────
#  DES TABLES
# ─────────────────────────────────────────────

IP = [
    58,50,42,34,26,18,10,2, 60,52,44,36,28,20,12,4,
    62,54,46,38,30,22,14,6, 64,56,48,40,32,24,16,8,
    57,49,41,33,25,17, 9,1, 59,51,43,35,27,19,11,3,
    61,53,45,37,29,21,13,5, 63,55,47,39,31,23,15,7,
]
IP_INV = [
    40,8,48,16,56,24,64,32, 39,7,47,15,55,23,63,31,
    38,6,46,14,54,22,62,30, 37,5,45,13,53,21,61,29,
    36,4,44,12,52,20,60,28, 35,3,43,11,51,19,59,27,
    34,2,42,10,50,18,58,26, 33,1,41, 9,49,17,57,25,
]
E = [
    32, 1, 2, 3, 4, 5,  4, 5, 6, 7, 8, 9,
     8, 9,10,11,12,13, 12,13,14,15,16,17,
    16,17,18,19,20,21, 20,21,22,23,24,25,
    24,25,26,27,28,29, 28,29,30,31,32, 1,
]
P = [
    16, 7,20,21,29,12,28,17, 1,15,23,26, 5,18,31,10,
     2, 8,24,14,32,27, 3, 9,19,13,30, 6,22,11, 4,25,
]
PC1_C = [57,49,41,33,25,17, 9, 1,58,50,42,34,26,18,
         10, 2,59,51,43,35,27,19,11, 3,60,52,44,36]
PC1_D = [63,55,47,39,31,23,15, 7,62,54,46,38,30,22,
         14, 6,61,53,45,37,29,21,13, 5,28,20,12, 4]
PC2 = [
    14,17,11,24, 1, 5, 3,28,15, 6,21,10,23,19,12, 4,
    26, 8,16, 7,27,20,13, 2,41,52,31,37,47,55,30,40,
    51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32,
]
SHIFTS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

S_BOXES = [
    [[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],[0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],[4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],[15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]],
    [[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],[3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],[0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],[13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]],
    [[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],[13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],[13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],[1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]],
    [[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],[13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],[10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],[3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]],
    [[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],[14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],[4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],[11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]],
    [[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],[10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],[9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],[4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]],
    [[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],[13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],[1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],[6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]],
    [[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],[1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],[7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],[2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]],
]

# ─────────────────────────────────────────────
#  DES BIT PRIMITIVES
# ─────────────────────────────────────────────
#DES Bit Primitives: bytes_to_bits, bits_to_bytes, permute, xor_bits, feistel
def bytes_to_bits(b):
    bits = []
    for byte in b:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits

def bits_to_bytes(bits):
    result = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        result.append(byte)
    return bytes(result)

def permute(bits, table):
    return [bits[t - 1] for t in table]

def xor_bits(a, b):
    return [x ^ y for x, y in zip(a, b)]

def feistel(R, K):
    """Standard DES Feistel function."""
    expanded = permute(R, E)
    xored = xor_bits(expanded, K)
    sbox_out = []
    for i in range(8):
        chunk = xored[i*6:(i+1)*6]
        row = (chunk[0] << 1) | chunk[5]
        col = (chunk[1] << 3) | (chunk[2] << 2) | (chunk[3] << 1) | chunk[4]
        val = S_BOXES[i][row][col]
        for b in range(3, -1, -1):
            sbox_out.append((val >> b) & 1)
    return permute(sbox_out, P)

# ─────────────────────────────────────────────
#  STANDARD DES KEY SCHEDULE
# ─────────────────────────────────────────────
#Standard DES key schedule: des_key_schedule
def des_key_schedule(key_8bytes: bytes) -> list:
    """
    Derive 16 DES round keys (each 48 bits) from a standard 8-byte / 64-bit key.
    Uses the real DES PC1 + shift + PC2 schedule.
    """
    key_bits = bytes_to_bits(key_8bytes)
    C = [key_bits[b - 1] for b in PC1_C]
    D = [key_bits[b - 1] for b in PC1_D]
    round_keys = []
    for shift in SHIFTS:
        C = C[shift:] + C[:shift]
        D = D[shift:] + D[:shift]
        CD = C + D
        # PC2 indexes into a 56-bit CD array
        k48 = [CD[b - 1] for b in PC2]
        round_keys.append(k48)
    return round_keys

# ─────────────────────────────────────────────
#  STANDARD DES BLOCK ENCRYPT (ECB, 64-bit)
# ─────────────────────────────────────────────
#  STANDARD DES BLOCK ENCRYPT (ECB, 64-bit)
def des_encrypt_block(block_8: bytes, key_8: bytes) -> bytes:
    """
    Encrypt a single 8-byte block with standard DES (ECB, no padding).
    key_8 must be exactly 8 bytes (64 bits, parity bits ignored).
    """
    round_keys = des_key_schedule(key_8)
    bits = permute(bytes_to_bits(block_8), IP)
    L, R = bits[:32], bits[32:]
    for K in round_keys:
        L, R = R, xor_bits(L, feistel(R, K))
    return bits_to_bytes(permute(R + L, IP_INV))

def des_decrypt_block(block_8: bytes, key_8: bytes) -> bytes:
    """Decrypt a single 8-byte DES block."""
    round_keys = list(reversed(des_key_schedule(key_8)))
    bits = permute(bytes_to_bits(block_8), IP)
    L, R = bits[:32], bits[32:]
    for K in round_keys:
        L, R = R, xor_bits(L, feistel(R, K))
    return bits_to_bytes(permute(R + L, IP_INV))

# ─────────────────────────────────────────────
#  XDES-A KEY DERIVATION  (Argon2id)
# ─────────────────────────────────────────────
#  XDES-A KEY DERIVATION  (Argon2id)
KDF_TOTAL   = 8 + 112 + 8 + 24   # 152 bytes
ARGON2_T    = 2
ARGON2_M    = 65536
ARGON2_P    = 1

def derive_keys(password: bytes, salt: bytes) -> dict:
    raw = hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=ARGON2_T,
        memory_cost=ARGON2_M,
        parallelism=ARGON2_P,
        hash_len=KDF_TOTAL,
        type=Type.ID,
    )
    k_pre        = raw[0:8]
    k_rounds_raw = raw[8:120]
    k_post       = raw[120:128]
    k_mac        = raw[128:152]

    round_keys = []
    for i in range(16):
        chunk   = k_rounds_raw[i*7:(i+1)*7]
        padded  = chunk + bytes(1)
        bits_56 = bytes_to_bits(padded)[:56]
        k48     = permute(bits_56, PC2)
        round_keys.append(k48)

    return {
        "pre":    k_pre,
        "rounds": round_keys,
        "post":   k_post,
        "mac":    k_mac,
        "raw":    raw,
    }

# ─────────────────────────────────────────────
#  XDES-A BLOCK CIPHER  (128-bit block)
# ─────────────────────────────────────────────
#  XDES-A BLOCK CIPHER  (128-bit block)
def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def _feistel_half(block_8: bytes, subkeys: list, encrypt: bool) -> bytes:
    keys = subkeys if encrypt else list(reversed(subkeys))
    bits = permute(bytes_to_bits(block_8), IP)
    L, R = bits[:32], bits[32:]
    for K in keys:
        L, R = R, xor_bits(L, feistel(R, K))
    return bits_to_bytes(permute(R + L, IP_INV))

def xdes_encrypt_block(block_16: bytes, keys: dict) -> bytes:
    L = block_16[:8]
    R = block_16[8:]
    L = _xor_bytes(L, keys["pre"])
    R = _xor_bytes(R, keys["pre"])
    rounds = keys["rounds"]
    L = _feistel_half(L, rounds[:8],  encrypt=True)
    R = _feistel_half(R, rounds[:8],  encrypt=True)
    L, R = _xor_bytes(L, R), _xor_bytes(R, L)
    L = _feistel_half(L, rounds[8:], encrypt=True)
    R = _feistel_half(R, rounds[8:], encrypt=True)
    L = _xor_bytes(L, keys["post"])
    R = _xor_bytes(R, keys["post"])
    return L + R

def xdes_decrypt_block(block_16: bytes, keys: dict) -> bytes:
    L = block_16[:8]
    R = block_16[8:]
    L = _xor_bytes(L, keys["post"])
    R = _xor_bytes(R, keys["post"])
    rounds = keys["rounds"]
    L = _feistel_half(L, rounds[8:], encrypt=False)
    R = _feistel_half(R, rounds[8:], encrypt=False)
    L, R = _xor_bytes(L, R), _xor_bytes(R, L)
    L = _feistel_half(L, rounds[:8], encrypt=False)
    R = _feistel_half(R, rounds[:8], encrypt=False)
    L = _xor_bytes(L, keys["pre"])
    R = _xor_bytes(R, keys["pre"])
    return L + R

# ─────────────────────────────────────────────
#  CTR MODE
# ─────────────────────────────────────────────
#  CTR MODE
def _ctr_keystream_block(nonce: bytes, counter: int, keys: dict) -> bytes:
    ctr_block = nonce[:8] + struct.pack(">Q", counter)
    return xdes_encrypt_block(ctr_block, keys)

def ctr_encrypt(plaintext: bytes, keys: dict, nonce: bytes) -> bytes:
    out = bytearray()
    for i in range(0, len(plaintext), 16):
        chunk = plaintext[i:i+16]
        ks    = _ctr_keystream_block(nonce, i // 16, keys)
        out  += bytes(p ^ k for p, k in zip(chunk, ks[:len(chunk)]))
    return bytes(out)

# ─────────────────────────────────────────────
#  FULL XDES-A PIPELINE
# ─────────────────────────────────────────────
#  FULL XDES-A PIPELINE
def xdes_a_encrypt(plaintext: bytes, password: bytes):
    argon_salt = os.urandom(16)
    nonce      = os.urandom(8)
    keys       = derive_keys(password, argon_salt)
    ciphertext = ctr_encrypt(plaintext, keys, nonce)
    tag        = hmac.new(keys["mac"], nonce + ciphertext, hashlib.sha256).digest()[:16]
    packet     = argon_salt + nonce + ciphertext + tag
    return argon_salt, nonce, ciphertext, tag, packet, keys

def xdes_a_decrypt(packet: bytes, password: bytes):
    if len(packet) < 16 + 8 + 16:
        raise ValueError("Packet too short.")
    argon_salt = packet[:16]
    nonce      = packet[16:24]
    tag_recv   = packet[-16:]
    ciphertext = packet[24:-16]
    keys       = derive_keys(password, argon_salt)
    tag_calc   = hmac.new(keys["mac"], nonce + ciphertext, hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(tag_recv, tag_calc):
        raise ValueError("MAC verification failed — data tampered or wrong key.")
    plaintext  = ctr_encrypt(ciphertext, keys, nonce)
    return argon_salt, nonce, ciphertext, tag_recv, plaintext, keys

# ─────────────────────────────────────────────
#  AVALANCHE ANALYSIS
# ─────────────────────────────────────────────

def avalanche_analysis(plaintext: bytes, password: bytes):
    pt   = (plaintext + bytes(16))[:16]
    keys = derive_keys(password, bytes(16))
    base_ct = xdes_encrypt_block(pt, keys)
    results = []
    for bit_pos in range(128):
        byte_idx = bit_pos // 8
        bit_idx  = 7 - (bit_pos % 8)
        flipped  = bytearray(pt)
        flipped[byte_idx] ^= (1 << bit_idx)
        fc   = xdes_encrypt_block(bytes(flipped), keys)
        diff = sum(bin(x ^ y).count('1') for x, y in zip(base_ct, fc))
        results.append(diff)
    avg = sum(results) / 128
    return avg, (avg / 128) * 100, results

# ─────────────────────────────────────────────
#  BRUTE FORCE HELPERS
# ─────────────────────────────────────────────

WEAK_PASSWORDS = [
    "password", "123456", "qwerty", "abc123", "letmein",
    "monkey", "dragon", "master", "sunshine", "princess",
    "admin", "login", "welcome", "shadow", "superman",
    "iloveyou", "trustno1", "hello", "password1", "test",
]

def estimate_crack_time(password: str) -> dict:
    charset = 0
    if any(c.islower() for c in password): charset += 26
    if any(c.isupper() for c in password): charset += 26
    if any(c.isdigit() for c in password): charset += 10
    if any(not c.isalnum() for c in password): charset += 32
    charset = max(charset, 1)

    keyspace      = charset ** len(password)
    SHA256_RATE   = 10_000_000_000
    ARGON2_RATE   = 10

    sha_secs  = keyspace / 2 / SHA256_RATE
    arg_secs  = keyspace / 2 / ARGON2_RATE

    def fmt(secs):
        if secs < 1:         return "< 1 second",       "CRITICAL"
        if secs < 60:        return f"{secs:.1f}s",      "CRITICAL"
        if secs < 3600:      return f"{secs/60:.1f} min","WEAK"
        if secs < 86400:     return f"{secs/3600:.1f} hr","WEAK"
        if secs < 2592000:   return f"{secs/86400:.1f} days","MODERATE"
        if secs < 31536000:  return f"{secs/2592000:.1f} mo","STRONG"
        y = secs / 31536000
        if y < 1e6:          return f"{y:,.0f} yrs",    "STRONG"
        if y < 1e12:         return f"{y:.2e} yrs",     "VERY STRONG"
        return f"{y:.2e} yrs", "UNBREAKABLE"

    sha_str,  sha_rating = fmt(sha_secs)
    arg_str,  arg_rating = fmt(arg_secs)

    return {
        "length":          len(password),
        "charset":         charset,
        "keyspace":        keyspace,
        "sha256_secs":     sha_secs,
        "sha256_str":      sha_str,
        "sha256_rating":   sha_rating,
        "argon2_secs":     arg_secs,
        "argon2_str":      arg_str,
        "argon2_rating":   arg_rating,
        "slowdown_factor": arg_secs / max(sha_secs, 1e-9),
    }

# ─────────────────────────────────────────────
#  LIVE BRUTE FORCE ENGINE  (CPU single-thread)
# ─────────────────────────────────────────────

import time
import itertools

BRUTE_CHARSET_ALPHA    = "abcdefghijklmnopqrstuvwxyz"
BRUTE_CHARSET_ALPHANUM = "abcdefghijklmnopqrstuvwxyz0123456789"
BRUTE_CHARSET_COMMON   = "abcdefghijklmnopqrstuvwxyz0123456789!@#"

def _candidate_to_des_key(candidate: str) -> bytes:
    """Stretch/truncate a short candidate string to exactly 8 bytes for DES."""
    raw = candidate.encode("utf-8")
    key = (raw * ((8 // len(raw)) + 1))[:8]
    return key

def brute_force_des(
    target_ct: bytes,
    known_pt: bytes,
    max_len: int,
    charset: str,
    stop_event,
    on_attempt,
    on_done,
):
    """
    Brute-force standard DES (single-threaded CPU).
    Encrypts known_pt with each candidate key and compares to target_ct.
    """
    attempt = 0
    start   = time.perf_counter()

    for length in range(1, max_len + 1):
        for combo in itertools.product(charset, repeat=length):
            if stop_event.is_set():
                on_done(False, "", attempt, time.perf_counter() - start)
                return

            candidate = "".join(combo)
            attempt  += 1
            key8      = _candidate_to_des_key(candidate)
            ct        = des_encrypt_block(known_pt[:8], key8)
            elapsed   = time.perf_counter() - start

            found = (ct == target_ct)
            on_attempt(attempt, candidate, elapsed, found)

            if found:
                on_done(True, candidate, attempt, elapsed)
                return

    on_done(False, "", attempt, time.perf_counter() - start)


def brute_force_xdes(
    target_ct: bytes,
    known_pt: bytes,
    argon_salt: bytes,
    max_len: int,
    charset: str,
    stop_event,
    on_attempt,
    on_done,
):
    """
    Brute-force XDES-A (single-threaded CPU).
    For each candidate password, runs the full Argon2id KDF + block encrypt
    and compares the first 16 bytes of the encrypted block to target_ct.
    """
    attempt = 0
    start   = time.perf_counter()

    for length in range(1, max_len + 1):
        for combo in itertools.product(charset, repeat=length):
            if stop_event.is_set():
                on_done(False, "", attempt, time.perf_counter() - start)
                return

            candidate = "".join(combo)
            attempt  += 1
            pw_b      = candidate.encode("utf-8")

            keys = derive_keys(pw_b, argon_salt)
            pt16 = (known_pt + bytes(16))[:16]
            ct   = xdes_encrypt_block(pt16, keys)

            elapsed = time.perf_counter() - start
            found   = (ct == target_ct)

            on_attempt(attempt, candidate, elapsed, found)

            if found:
                on_done(True, candidate, attempt, elapsed)
                return

    on_done(False, "", attempt, time.perf_counter() - start)


# ─────────────────────────────────────────────
#  GPU / MULTIPROCESSING BRUTE FORCE  (import from gpu_bruteforce.py)
#
#  ui.py imports these two names from cipher.py, so we re-export them here.
#  gpu_bruteforce.py auto-detects CUDA and falls back to multiprocessing.
# ─────────────────────────────────────────────

try:
    from gpu_bruteforce import brute_force_des_gpu, brute_force_xdes_gpu  # noqa: F401
except ImportError:
    # If gpu_bruteforce.py isn't present, provide plain multiprocessing stubs
    # that match the same API so the UI never crashes.
    import multiprocessing as _mp

    def _des_mp_worker(args):
        candidate, pt8, tct = args
        from cipher import des_encrypt_block, _candidate_to_des_key
        key8 = _candidate_to_des_key(candidate)
        return candidate, des_encrypt_block(pt8, key8) == tct

    def _xdes_mp_worker(args):
        candidate, known_pt, argon_salt, tct = args
        from cipher import derive_keys, xdes_encrypt_block
        keys = derive_keys(candidate.encode(), argon_salt)
        pt16 = (known_pt + bytes(16))[:16]
        return candidate, xdes_encrypt_block(pt16, keys) == tct

    def _mp_engine(worker_fn, items, target_ct, stop_event,
                   on_attempt, on_done, num_workers):
        attempt = 0
        start   = time.perf_counter()
        batch   = []
        BATCH   = 512

        with _mp.Pool(num_workers) as pool:
            for item in items:
                if stop_event.is_set():
                    pool.terminate()
                    on_done(False, "", attempt, time.perf_counter() - start)
                    return
                batch.append(item)
                if len(batch) >= BATCH:
                    for candidate, found in pool.imap_unordered(worker_fn, batch):
                        attempt += 1
                        elapsed  = time.perf_counter() - start
                        on_attempt(attempt, candidate, elapsed, found)
                        if found:
                            pool.terminate()
                            on_done(True, candidate, attempt, elapsed)
                            return
                    batch = []
            for candidate, found in pool.imap_unordered(worker_fn, batch):
                attempt += 1
                elapsed  = time.perf_counter() - start
                on_attempt(attempt, candidate, elapsed, found)
                if found:
                    pool.terminate()
                    on_done(True, candidate, attempt, elapsed)
                    return

        on_done(False, "", attempt, time.perf_counter() - start)

    def brute_force_des_gpu(target_ct, known_pt, max_len, charset,
                            stop_event, on_attempt, on_done, num_workers=4):
        pt8   = (known_pt[:8] + bytes(8))[:8]
        items = (
            ("".join(c), pt8, target_ct)
            for ln in range(1, max_len + 1)
            for c  in itertools.product(charset, repeat=ln)
        )
        _mp_engine(_des_mp_worker, items, target_ct,
                   stop_event, on_attempt, on_done, num_workers)

    def brute_force_xdes_gpu(target_ct, known_pt, argon_salt, max_len,
                             charset, stop_event, on_attempt, on_done, num_workers=4):
        items = (
            ("".join(c), known_pt, argon_salt, target_ct)
            for ln in range(1, max_len + 1)
            for c  in itertools.product(charset, repeat=ln)
        )
        _mp_engine(_xdes_mp_worker, items, target_ct,
                   stop_event, on_attempt, on_done, num_workers)
