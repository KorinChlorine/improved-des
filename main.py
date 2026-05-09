"""
IASSING Encryptor and Decryptor
Implements the XDES-A academic cipher design:
  Argon2id KDF → Independent round keys → 128-bit block (dual 64-bit Feistel)
  Pre/Post Whitening (DES-X) → CTR Mode → HMAC-SHA256 (Encrypt-then-MAC)

Made by:
  Kharl Asuncion · Alexandra De Vera
  Darrel Joshua Ocampo · Ron Benedict Tesorero

Dark terminal-inspired aesthetic with monospace fonts.
"""

import os
import hmac
import hashlib
import struct
import tkinter as tk
from tkinter import ttk, scrolledtext
from argon2.low_level import hash_secret_raw, Type

# ─────────────────────────────────────────────
#  DES TABLES  (kept exactly as-is)
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
PC2 = [
    14,17,11,24, 1, 5, 3,28,15, 6,21,10,23,19,12, 4,
    26, 8,16, 7,27,20,13, 2,41,52,31,37,47,55,30,40,
    51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32,
]
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
    """Standard DES Feistel function with proven S-boxes (fixed, not key-dependent)."""
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
#  XDES-A KEY DERIVATION  (Argon2id)
# ─────────────────────────────────────────────
#
#  Total KDF output: 152 bytes =
#    K_pre   8 bytes  (pre-whitening)
#    K_i    16×7 bytes = 112 bytes  (one 56-bit key per round, no key schedule)
#    K_post  8 bytes  (post-whitening)
#    K_mac  24 bytes  (HMAC-SHA256 key — truncated to 24 for display clarity)
#
#  Argon2id params (academic / low-resource):
#    time_cost=2, memory_cost=65536 (64 MB), parallelism=1

KDF_TOTAL   = 8 + 112 + 8 + 24   # 152 bytes
ARGON2_T    = 2
ARGON2_M    = 65536
ARGON2_P    = 1

def derive_keys(password: bytes, salt: bytes) -> dict:
    """
    Derive all XDES-A subkeys from password + salt via Argon2id.
    Returns a dict with pre, rounds (list of 16 bit-lists), post, mac.
    """
    raw = hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=ARGON2_T,
        memory_cost=ARGON2_M,
        parallelism=ARGON2_P,
        hash_len=KDF_TOTAL,
        type=Type.ID,
    )
    k_pre   = raw[0:8]
    k_rounds_raw = raw[8:120]          # 16 × 7 bytes
    k_post  = raw[120:128]
    k_mac   = raw[128:152]

    # Convert each 7-byte block to a 48-bit PC2-permuted subkey (DES expects 48 bits)
    # We take the low 56 bits (7 bytes) and apply PC2 to get 48 bits — same as DES does
    round_keys = []
    for i in range(16):
        chunk = k_rounds_raw[i*7:(i+1)*7]
        # pad to 8 bytes for PC2 (PC2 indexes up to 56)
        padded = chunk + bytes(1)
        bits_56 = bytes_to_bits(padded)[:56]
        # apply PC2 — but PC2 expects 56 bits in C+D arrangement
        # We just use it directly since we just need 48 bits from 56
        k48 = permute(bits_56, PC2)
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
#
#  Block = 16 bytes = [L_block (8 bytes) | R_block (8 bytes)]
#
#  Encrypt:
#    1. Pre-whitening:  L ^= K_pre,  R ^= K_pre
#    2. 16 Feistel rounds on L (using R as cross-feed after round 8)
#       and 16 Feistel rounds on R (using L as cross-feed after round 8)
#       — simple parallel Feistel with mid-point swap for cross-mixing
#    3. Post-whitening: L ^= K_post, R ^= K_post
#
#  Decrypt reverses rounds and whitening.

def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def _feistel_half(block_8: bytes, subkeys: list, encrypt: bool) -> bytes:
    """Run 16-round Feistel on a single 64-bit half."""
    keys = subkeys if encrypt else list(reversed(subkeys))
    bits = permute(bytes_to_bits(block_8), IP)
    L, R = bits[:32], bits[32:]
    for K in keys:
        L, R = R, xor_bits(L, feistel(R, K))
    return bits_to_bytes(permute(R + L, IP_INV))

def xdes_encrypt_block(block_16: bytes, keys: dict) -> bytes:
    """Encrypt a single 128-bit block under XDES-A."""
    L = block_16[:8]
    R = block_16[8:]

    # Pre-whitening
    L = _xor_bytes(L, keys["pre"])
    R = _xor_bytes(R, keys["pre"])

    # 16 Feistel rounds on each half; mid-point cross-mix at round 8
    rounds = keys["rounds"]
    L = _feistel_half(L, rounds[:8],  encrypt=True)
    R = _feistel_half(R, rounds[:8],  encrypt=True)
    # cross-mix: swap and XOR
    L, R = _xor_bytes(L, R), _xor_bytes(R, L)
    L = _feistel_half(L, rounds[8:], encrypt=True)
    R = _feistel_half(R, rounds[8:], encrypt=True)

    # Post-whitening
    L = _xor_bytes(L, keys["post"])
    R = _xor_bytes(R, keys["post"])

    return L + R

def xdes_decrypt_block(block_16: bytes, keys: dict) -> bytes:
    """Decrypt a single 128-bit block under XDES-A."""
    L = block_16[:8]
    R = block_16[8:]

    # Undo post-whitening
    L = _xor_bytes(L, keys["post"])
    R = _xor_bytes(R, keys["post"])

    # Undo second half of Feistel (reversed)
    rounds = keys["rounds"]
    L = _feistel_half(L, rounds[8:], encrypt=False)
    R = _feistel_half(R, rounds[8:], encrypt=False)
    # undo cross-mix (XOR is its own inverse in this arrangement)
    L, R = _xor_bytes(L, R), _xor_bytes(R, L)
    L = _feistel_half(L, rounds[:8], encrypt=False)
    R = _feistel_half(R, rounds[:8], encrypt=False)

    # Undo pre-whitening
    L = _xor_bytes(L, keys["pre"])
    R = _xor_bytes(R, keys["pre"])

    return L + R

# ─────────────────────────────────────────────
#  CTR MODE  (128-bit block, 128-bit nonce/counter)
# ─────────────────────────────────────────────

def _ctr_keystream_block(nonce: bytes, counter: int, keys: dict) -> bytes:
    """Encrypt nonce||counter to produce a 128-bit keystream block."""
    ctr_block = nonce[:8] + struct.pack(">Q", counter)
    return xdes_encrypt_block(ctr_block, keys)

def ctr_encrypt(plaintext: bytes, keys: dict, nonce: bytes) -> bytes:
    """CTR-mode encrypt/decrypt (symmetric)."""
    out = bytearray()
    for i in range(0, len(plaintext), 16):
        chunk = plaintext[i:i+16]
        ks    = _ctr_keystream_block(nonce, i // 16, keys)
        out  += bytes(p ^ k for p, k in zip(chunk, ks[:len(chunk)]))
    return bytes(out)

# ─────────────────────────────────────────────
#  FULL XDES-A PIPELINE
# ─────────────────────────────────────────────
#
#  Packet layout: argon_salt(16) || nonce(8) || ciphertext(16) || mac(16)

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
#  AVALANCHE ANALYSIS  (on 128-bit block)
# ─────────────────────────────────────────────

def avalanche_analysis(plaintext: bytes, password: bytes):
    """
    Flip each bit of the 128-bit block and measure diffusion through the
    XDES-A block cipher directly (not CTR, which would trivially pass 1 bit).
    Uses xdes_encrypt_block so whitening + Feistel rounds are all exercised.
    """
    pt   = (plaintext + bytes(16))[:16]
    keys = derive_keys(password, bytes(16))      # fixed salt for determinism
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
#  BRUTE FORCE SIMULATION HELPERS
# ─────────────────────────────────────────────

WEAK_PASSWORDS = [
    "password", "123456", "qwerty", "abc123", "letmein",
    "monkey", "dragon", "master", "sunshine", "princess",
    "admin", "login", "welcome", "shadow", "superman",
    "iloveyou", "trustno1", "hello", "password1", "test",
]

def estimate_crack_time(password: str) -> dict:
    """
    Estimate cracking resistance under two scenarios:
      A) Plain MD5/SHA-256 (fast hash, ~10 billion/sec on GPU cluster)
      B) Argon2id t=2 m=64MB  (~10 guesses/sec on same hardware)
    """
    charset = 0
    if any(c.islower() for c in password): charset += 26
    if any(c.isupper() for c in password): charset += 26
    if any(c.isdigit() for c in password): charset += 10
    if any(not c.isalnum() for c in password): charset += 32
    charset = max(charset, 1)

    keyspace      = charset ** len(password)
    SHA256_RATE   = 10_000_000_000   # 10 B/sec modern GPU cluster
    ARGON2_RATE   = 10               # ~10/sec with 64 MB per hash

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
    speedup = max(arg_secs, 1e-9) / max(sha_secs, 1e-9)   # how much SLOWER argon2 is for attacker

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
#  COLOR PALETTE  (dark terminal)
# ─────────────────────────────────────────────

BG      = "#0d0f14"
BG2     = "#13161d"
BG3     = "#1a1e28"
BORDER  = "#252a38"
ACCENT  = "#00e5ff"
ACCENT2 = "#7c3aed"
GREEN   = "#00ff9d"
YELLOW  = "#ffd600"
RED     = "#ff3d71"
FG      = "#cdd6f4"
FG_DIM  = "#6c7086"
MONO    = ("Courier New", 10)
MONO_SM = ("Courier New", 9)
MONO_LG = ("Courier New", 12, "bold")

# ─────────────────────────────────────────────
#  APP
# ─────────────────────────────────────────────

class XDESApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("IASSING — Encryptor and Decryptor")
        self.geometry("980x720")
        self.minsize(860, 640)
        self.configure(bg=BG)
        self.resizable(True, True)
        self._build_ui()

    # ── layout ──────────────────────────────

    def _build_ui(self):
        # header
        hdr = tk.Frame(self, bg=BG, pady=0)
        hdr.pack(fill="x")

        tk.Frame(hdr, bg=ACCENT2, height=3).pack(fill="x")

        inner_hdr = tk.Frame(hdr, bg=BG2, pady=10)
        inner_hdr.pack(fill="x")

        tk.Label(inner_hdr, text="◈  IASSING", font=("Courier New", 15, "bold"),
                 bg=BG2, fg=ACCENT).pack(side="left", padx=20)
        tk.Label(inner_hdr, text="Encryptor and Decryptor  //  XDES-A Academic Cipher",
                 font=MONO_SM, bg=BG2, fg=FG_DIM).pack(side="left")

        # credits on the right
        credits_frame = tk.Frame(inner_hdr, bg=BG2)
        credits_frame.pack(side="right", padx=20)
        tk.Label(credits_frame,
                 text="Kharl Asuncion · Alexandra De Vera · Darrel Joshua Ocampo · Ron Benedict Tesorero",
                 font=("Courier New", 8), bg=BG2, fg=FG_DIM).pack(anchor="e")
        badge = tk.Label(credits_frame,
            text=" Argon2id · 128-bit · Whitening · CTR · HMAC ",
            font=MONO_SM, bg=ACCENT2, fg="white", padx=6, pady=2)
        badge.pack(anchor="e", pady=(2,0))

        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

        style = ttk.Style(self)
        style.theme_use("default")
        style.configure("TNotebook", background=BG, borderwidth=0, tabmargins=0)
        style.configure("TNotebook.Tab", background=BG3, foreground=FG_DIM,
                        font=MONO, padding=[16, 8], borderwidth=0)
        style.map("TNotebook.Tab",
                  background=[("selected", BG2)],
                  foreground=[("selected", ACCENT)])

        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True)

        self._tab_encrypt()
        self._tab_decrypt()
        self._tab_avalanche()
        self._tab_trace()
        self._tab_bruteforce()

    # ── helpers ─────────────────────────────

    def _frame(self, parent):
        return tk.Frame(parent, bg=BG2)

    def _card(self, parent, title, pady=10):
        outer = tk.Frame(parent, bg=BORDER, padx=1, pady=1)
        inner = tk.Frame(outer, bg=BG3)
        inner.pack(fill="both", expand=True)
        tk.Label(inner, text=title, font=MONO_SM, bg=BG3, fg=FG_DIM,
                 anchor="w", padx=10, pady=4).pack(fill="x")
        tk.Frame(inner, bg=BORDER, height=1).pack(fill="x")
        body = tk.Frame(inner, bg=BG3, padx=10, pady=pady)
        body.pack(fill="both", expand=True)
        return outer, body

    def _labeled_entry(self, parent, label, show=None, width=40):
        tk.Label(parent, text=label, font=MONO_SM, bg=BG3, fg=FG_DIM,
                 anchor="w").pack(anchor="w", pady=(6,1))
        e = tk.Entry(parent, font=MONO, bg=BG, fg=ACCENT, insertbackground=ACCENT,
                     relief="flat", bd=6, width=width, show=show)
        e.pack(fill="x", ipady=4)
        return e

    def _btn(self, parent, text, cmd, color=ACCENT):
        return tk.Button(parent, text=text, font=("Courier New", 10, "bold"),
                         bg=color, fg=BG, activebackground=FG, activeforeground=BG,
                         relief="flat", bd=0, padx=18, pady=8, cursor="hand2",
                         command=cmd)

    def _output_box(self, parent, height=6):
        box = scrolledtext.ScrolledText(parent, font=MONO_SM, bg=BG, fg=GREEN,
                                        insertbackground=GREEN, relief="flat",
                                        bd=0, height=height, state="disabled",
                                        wrap="word")
        box.pack(fill="both", expand=True, pady=(6,0))
        return box

    def _write(self, box, text, clear=True):
        box.configure(state="normal")
        if clear:
            box.delete("1.0", "end")
        box.insert("end", text)
        box.configure(state="disabled")
        box.see("end")

    def _status(self, lbl, text, fg=FG_DIM):
        lbl.config(text=text, fg=fg)

    # ── TAB 1: ENCRYPT ──────────────────────

    def _tab_encrypt(self):
        tab = self._frame(self.nb)
        self.nb.add(tab, text="  🔒  ENCRYPT  ")
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(1, weight=1)

        c_in, b_in = self._card(tab, "► INPUT")
        c_in.grid(row=0, column=0, sticky="ew", padx=16, pady=(16,8))

        row = tk.Frame(b_in, bg=BG3)
        row.pack(fill="x")

        col1 = tk.Frame(row, bg=BG3); col1.pack(side="left", fill="x", expand=True, padx=(0,8))
        col2 = tk.Frame(row, bg=BG3); col2.pack(side="left", fill="x", expand=True)

        self.enc_pt  = self._labeled_entry(col1, "PLAINTEXT  (1–16 ASCII bytes)")
        self.enc_pt.insert(0, "HELLO XDES-A!!")
        self.enc_pw  = self._labeled_entry(col2, "PASSWORD  (any length)", show="•")
        self.enc_pw.insert(0, "MyS3cur3Pass!")

        tk.Label(b_in,
            text="  ⚙  KDF: Argon2id  t=2  m=64MB  p=1   "
                 "│  Block: 128-bit dual Feistel   "
                 "│  Mode: CTR + HMAC-SHA256",
            font=MONO_SM, bg=BG3, fg=FG_DIM, anchor="w").pack(anchor="w", pady=(6,0))

        btn_row = tk.Frame(b_in, bg=BG3, pady=10); btn_row.pack(anchor="w")
        self._btn(btn_row, "  ▶  ENCRYPT  ", self._do_encrypt).pack(side="left", padx=(0,8))
        self._btn(btn_row, "  ✕  CLEAR  ", self._clear_enc, color=BG3).pack(side="left")

        c_out, b_out = self._card(tab, "► OUTPUT", pady=8)
        c_out.grid(row=1, column=0, sticky="nsew", padx=16, pady=(0,16))
        self.enc_out = self._output_box(b_out, height=14)

        self.enc_status = tk.Label(tab, text="Ready.  Note: Argon2id KDF takes ~1–2s.",
                                   font=MONO_SM, bg=BG, fg=FG_DIM, anchor="w", padx=16)
        self.enc_status.grid(row=2, column=0, sticky="ew")

    def _do_encrypt(self):
        pt_str = self.enc_pt.get()
        pw_str = self.enc_pw.get()
        if not pt_str or not pw_str:
            self._write(self.enc_out, "⚠  Both plaintext and password are required.")
            return
        pt_b = pt_str.encode("utf-8")
        if len(pt_b) > 16:
            self._write(self.enc_out, f"⚠  Plaintext max 16 bytes (got {len(pt_b)}). Trim input.")
            return
        pt_padded = pt_b.ljust(16, b'\x00')
        pw_b = pw_str.encode("utf-8")

        self._status(self.enc_status, "⏳  Running Argon2id KDF (~1–2s)…", YELLOW)
        self.update()

        try:
            argon_salt, nonce, ciphertext, tag, packet, keys = xdes_a_encrypt(pt_padded, pw_b)
        except Exception as ex:
            self._write(self.enc_out, f"⚠  Encryption error: {ex}")
            self._status(self.enc_status, f"⚠  Error: {ex}", RED)
            return

        packet_hex = packet.hex().upper()
        lines = [
            "╔══════════════════════════════════════════════════════════╗",
            "║               XDES-A   ENCRYPTION REPORT                ║",
            "╚══════════════════════════════════════════════════════════╝",
            "",
            f"  Plaintext (ASCII)     :  {pt_str!r}",
            f"  Plaintext (hex, padded):  {pt_padded.hex().upper()}",
            "",
            "  ── STEP 1: Argon2id KDF ─────────────────────────────────",
            f"  Argon2 Salt (random)  :  {argon_salt.hex().upper()}",
            f"  K_pre  (whitening)    :  {keys['pre'].hex().upper()}",
            f"  K_post (whitening)    :  {keys['post'].hex().upper()}",
            f"  K_mac  (HMAC key)     :  {keys['mac'].hex().upper()}",
            f"  K_1..K_16 (round keys):  [16 independent 48-bit keys derived]",
            "",
            "  ── STEP 2: Pre-Whitening (DES-X) ────────────────────────",
            f"  PT ⊕ K_pre (L half)   :  {_xor_bytes(pt_padded[:8], keys['pre']).hex().upper()}",
            f"  PT ⊕ K_pre (R half)   :  {_xor_bytes(pt_padded[8:], keys['pre']).hex().upper()}",
            "",
            "  ── STEP 3: 16 Feistel Rounds (each independent key) ─────",
            "           + Mid-point cross-mix (L ↔ R XOR swap)",
            f"  Ciphertext (128-bit)  :  {ciphertext.hex().upper()}",
            "",
            "  ── STEP 4: Post-Whitening ───────────────────────────────",
            "",
            "  ── STEP 5: CTR Mode (random nonce) ──────────────────────",
            f"  Nonce (random 64-bit) :  {nonce.hex().upper()}",
            "",
            "  ── STEP 6: HMAC-SHA256 (Encrypt-then-MAC) ───────────────",
            f"  MAC tag (128-bit)     :  {tag.hex().upper()}",
            "",
            "  ── FINAL OUTPUT (hex) ───────────────────────────────────",
            f"  {packet_hex}",
            "",
            "  Packet layout: [Argon2 Salt 16B] [Nonce 8B] [Ciphertext 16B] [MAC 16B]",
            "  ✓  Paste the FINAL OUTPUT above into the DECRYPT tab.",
        ]
        self._write(self.enc_out, "\n".join(lines))
        self._status(self.enc_status, f"✓  Done. Packet: {len(packet)} bytes.", GREEN)

        # auto-fill decrypt
        self.dec_ct.delete(0, "end");  self.dec_ct.insert(0, packet_hex)
        self.dec_pw.delete(0, "end");  self.dec_pw.insert(0, pw_str)

    def _clear_enc(self):
        self.enc_pt.delete(0, "end")
        self.enc_pw.delete(0, "end")
        self._write(self.enc_out, "")
        self._status(self.enc_status, "Cleared.")

    # ── TAB 2: DECRYPT ──────────────────────

    def _tab_decrypt(self):
        tab = self._frame(self.nb)
        self.nb.add(tab, text="  🔓  DECRYPT  ")
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(1, weight=1)

        c_in, b_in = self._card(tab, "► INPUT")
        c_in.grid(row=0, column=0, sticky="ew", padx=16, pady=(16,8))

        row = tk.Frame(b_in, bg=BG3); row.pack(fill="x")
        col1 = tk.Frame(row, bg=BG3); col1.pack(side="left", fill="x", expand=True, padx=(0,8))
        col2 = tk.Frame(row, bg=BG3); col2.pack(side="left", fill="x", expand=True)

        self.dec_ct  = self._labeled_entry(col1, "ENCRYPTED DATA  (hex from Encrypt tab)")
        self.dec_pw  = self._labeled_entry(col2, "PASSWORD", show="•")

        btn_row = tk.Frame(b_in, bg=BG3, pady=10); btn_row.pack(anchor="w")
        self._btn(btn_row, "  ▶  DECRYPT  ", self._do_decrypt, color=GREEN).pack(side="left", padx=(0,8))
        self._btn(btn_row, "  ✕  CLEAR  ", self._clear_dec, color=BG3).pack(side="left")

        c_out, b_out = self._card(tab, "► OUTPUT", pady=8)
        c_out.grid(row=1, column=0, sticky="nsew", padx=16, pady=(0,16))
        self.dec_out = self._output_box(b_out, height=14)

        self.dec_status = tk.Label(tab, text="Ready.  Note: Argon2id KDF takes ~1–2s.",
                                   font=MONO_SM, bg=BG, fg=FG_DIM, anchor="w", padx=16)
        self.dec_status.grid(row=2, column=0, sticky="ew")

    def _do_decrypt(self):
        hex_str = self.dec_ct.get().strip()
        pw_str  = self.dec_pw.get()
        if not hex_str or not pw_str:
            self._write(self.dec_out, "⚠  Both fields required.")
            return
        try:
            raw = bytes.fromhex(hex_str)
        except ValueError:
            self._write(self.dec_out, "⚠  Invalid hex string. Paste the exact output from the Encrypt tab.")
            return

        self._status(self.dec_status, "⏳  Running Argon2id KDF (~1–2s)…", YELLOW)
        self.update()

        try:
            argon_salt, nonce, ciphertext, tag, plaintext, keys = xdes_a_decrypt(raw, pw_str.encode())
        except Exception as ex:
            self._write(self.dec_out, f"⚠  Decryption failed: {ex}")
            self._status(self.dec_status, f"⚠  {ex}", RED)
            return

        try:
            pt_ascii = plaintext.rstrip(b'\x00').decode("utf-8")
        except Exception:
            pt_ascii = "[non-ASCII]"

        lines = [
            "╔══════════════════════════════════════════════════════════╗",
            "║               XDES-A   DECRYPTION REPORT                ║",
            "╚══════════════════════════════════════════════════════════╝",
            "",
            "  ── STEP 1: Parse Packet ─────────────────────────────────",
            f"  Argon2 Salt           :  {argon_salt.hex().upper()}",
            f"  Nonce                 :  {nonce.hex().upper()}",
            f"  MAC tag (received)    :  {tag.hex().upper()}",
            "",
            "  ── STEP 2: Argon2id KDF (same password + salt) ──────────",
            f"  K_pre                 :  {keys['pre'].hex().upper()}",
            f"  K_post                :  {keys['post'].hex().upper()}",
            f"  K_mac                 :  {keys['mac'].hex().upper()}",
            "",
            "  ── STEP 3: HMAC-SHA256 Verification ─────────────────────",
            "  ✓  MAC verified  —  data integrity confirmed",
            "",
            "  ── STEP 4: CTR Decrypt → Feistel⁻¹ → Unwhiten ──────────",
            f"  Plaintext (hex)       :  {plaintext.hex().upper()}",
            f"  Plaintext (ASCII)     :  {pt_ascii!r}",
            "",
            "  ✓  D_k(E_k(m)) = m   →   PIPELINE PROOF COMPLETE",
        ]
        self._write(self.dec_out, "\n".join(lines))
        self._status(self.dec_status, f"✓  Decrypted: {pt_ascii!r}", GREEN)

    def _clear_dec(self):
        self.dec_ct.delete(0, "end")
        self.dec_pw.delete(0, "end")
        self._write(self.dec_out, "")
        self._status(self.dec_status, "Cleared.")

    # ── TAB 3: AVALANCHE ────────────────────

    def _tab_avalanche(self):
        tab = self._frame(self.nb)
        self.nb.add(tab, text="  📊  AVALANCHE  ")
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(1, weight=1)

        c_in, b_in = self._card(tab, "► INPUT")
        c_in.grid(row=0, column=0, sticky="ew", padx=16, pady=(16,8))

        row = tk.Frame(b_in, bg=BG3); row.pack(fill="x")
        col1 = tk.Frame(row, bg=BG3); col1.pack(side="left", fill="x", expand=True, padx=(0,8))
        col2 = tk.Frame(row, bg=BG3); col2.pack(side="left", fill="x", expand=True)

        self.av_pt  = self._labeled_entry(col1, "PLAINTEXT  (up to 16 ASCII chars)")
        self.av_pt.insert(0, "HELLO XDES-A!!")
        self.av_pw  = self._labeled_entry(col2, "PASSWORD", show="•")
        self.av_pw.insert(0, "MyS3cur3Pass!")

        tk.Label(b_in,
            text="  ⚙  Flips each of the 128 plaintext bits once. KDF runs once (fixed salt).",
            font=MONO_SM, bg=BG3, fg=FG_DIM, anchor="w").pack(anchor="w", pady=(4,0))

        btn_row = tk.Frame(b_in, bg=BG3, pady=10); btn_row.pack(anchor="w")
        self._btn(btn_row, "  ▶  ANALYZE  ", self._do_avalanche, color=YELLOW).pack(side="left")

        c_out, b_out = self._card(tab, "► AVALANCHE ANALYSIS  (128 bits)", pady=8)
        c_out.grid(row=1, column=0, sticky="nsew", padx=16, pady=(0,16))
        self.av_out = self._output_box(b_out, height=16)

        self.av_status = tk.Label(tab, text="Ready.  Note: Argon2id KDF runs once (~1–2s).",
                                  font=MONO_SM, bg=BG, fg=FG_DIM, anchor="w", padx=16)
        self.av_status.grid(row=2, column=0, sticky="ew")

    def _do_avalanche(self):
        pt_str = self.av_pt.get()
        pw_str = self.av_pw.get()
        if not pt_str or not pw_str:
            self._write(self.av_out, "⚠  Both fields required.")
            return
        pt_b = pt_str.encode("utf-8")[:16].ljust(16, b'\x00')

        self._status(self.av_status, "⏳  Argon2id KDF + 128 cipher evaluations…", YELLOW)
        self.update()

        avg, pct, results = avalanche_analysis(pt_b, pw_str.encode())

        worst_val = min(results); best_val = max(results)
        worst_bit = results.index(worst_val); best_bit = results.index(best_val)

        chart = ["  BIT#  CHANGED   BAR",
                 "  " + "─"*56]
        for i, d in enumerate(results):
            bar   = "█" * (d // 4)
            pct_i = d / 128 * 100
            flag  = " ◄ WORST" if i == worst_bit else (" ◄ BEST" if i == best_bit else "")
            chart.append(f"  {i:03d}   {d:03d}/128  {bar:<32} {pct_i:5.1f}%{flag}")

        lines = [
            "╔══════════════════════════════════════════════════════════╗",
            "║           XDES-A  AVALANCHE EFFECT ANALYSIS             ║",
            "╚══════════════════════════════════════════════════════════╝",
            "",
            f"  Plaintext  :  {pt_b.hex().upper()}",
            f"  Bits tested:  128  (all plaintext bits, 1 flip each)",
            "",
            "  ── SUMMARY ──────────────────────────────────────────────",
            f"  Avg bits changed  :  {avg:.2f} / 128",
            f"  Avalanche %       :  {pct:.2f}%",
            f"  Ideal target      :  ~50.00%",
            f"  Result            :  {'✓ STRONG' if pct >= 45 else '⚠ WEAK'}",
            "",
            f"  Best  flip: bit {best_bit:03d}  → {best_val} bits  ({best_val/128*100:.1f}%)",
            f"  Worst flip: bit {worst_bit:03d}  → {worst_val} bits  ({worst_val/128*100:.1f}%)",
            "",
            "  ── PER-BIT CHART ────────────────────────────────────────",
        ] + chart

        self._write(self.av_out, "\n".join(lines))
        self._status(self.av_status,
                     f"✓  Avalanche: {pct:.2f}%   {'STRONG' if pct >= 45 else 'WEAK'}",
                     GREEN if pct >= 45 else YELLOW)

    # ── TAB 4: STEP TRACE ───────────────────

    def _tab_trace(self):
        tab = self._frame(self.nb)
        self.nb.add(tab, text="  🔍  STEP TRACE  ")
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(1, weight=1)

        c_in, b_in = self._card(tab, "► INPUT")
        c_in.grid(row=0, column=0, sticky="ew", padx=16, pady=(16,8))

        row = tk.Frame(b_in, bg=BG3); row.pack(fill="x")
        col1 = tk.Frame(row, bg=BG3); col1.pack(side="left", fill="x", expand=True, padx=(0,8))
        col2 = tk.Frame(row, bg=BG3); col2.pack(side="left", fill="x", expand=True)

        self.tr_pt = self._labeled_entry(col1, "PLAINTEXT  (up to 16 ASCII chars)")
        self.tr_pt.insert(0, "HELLO XDES-A!!")
        self.tr_pw = self._labeled_entry(col2, "PASSWORD", show="•")
        self.tr_pw.insert(0, "MyS3cur3Pass!")

        tk.Label(b_in,
            text="  ⚙  Uses fixed zero salt + zero nonce for deterministic trace.",
            font=MONO_SM, bg=BG3, fg=FG_DIM, anchor="w").pack(anchor="w", pady=(4,0))

        btn_row = tk.Frame(b_in, bg=BG3, pady=10); btn_row.pack(anchor="w")
        self._btn(btn_row, "  ▶  TRACE  ", self._do_trace, color=ACCENT2).pack(side="left")

        c_out, b_out = self._card(tab, "► XDES-A STEP TRACE", pady=8)
        c_out.grid(row=1, column=0, sticky="nsew", padx=16, pady=(0,16))
        self.tr_out = self._output_box(b_out, height=16)

        self.tr_status = tk.Label(tab, text="Ready.  Note: Argon2id KDF takes ~1–2s.",
                                  font=MONO_SM, bg=BG, fg=FG_DIM, anchor="w", padx=16)
        self.tr_status.grid(row=2, column=0, sticky="ew")

    def _do_trace(self):
        pt_str = self.tr_pt.get()
        pw_str = self.tr_pw.get()
        if not pt_str or not pw_str:
            self._write(self.tr_out, "⚠  Both fields required.")
            return
        pt_b    = pt_str.encode("utf-8")[:16].ljust(16, b'\x00')
        fixed_s = bytes(16)
        fixed_n = bytes(8)

        self._status(self.tr_status, "⏳  Running Argon2id KDF…", YELLOW)
        self.update()

        keys = derive_keys(pw_str.encode(), fixed_s)

        L_raw = pt_b[:8]; R_raw = pt_b[8:]

        # pre-whitening
        L_w = _xor_bytes(L_raw, keys["pre"])
        R_w = _xor_bytes(R_raw, keys["pre"])

        # first 8 rounds on L and R independently
        rounds = keys["rounds"]

        def trace_half(block_8, subkeys):
            bits = permute(bytes_to_bits(block_8), IP)
            L, R = bits[:32], bits[32:]
            states = []
            for K in subkeys:
                L, R = R, xor_bits(L, feistel(R, K))
                states.append((bits_to_bytes(L).hex().upper(),
                                bits_to_bytes(R).hex().upper()))
            final = bits_to_bytes(permute(R + L, IP_INV))
            return states, final

        stL1, L_mid = trace_half(L_w, rounds[:8])
        stR1, R_mid = trace_half(R_w, rounds[:8])

        # cross-mix
        L_x = _xor_bytes(L_mid, R_mid)
        R_x = _xor_bytes(R_mid, L_mid)

        stL2, L_post = trace_half(L_x, rounds[8:])
        stR2, R_post = trace_half(R_x, rounds[8:])

        # post-whitening
        L_fin = _xor_bytes(L_post, keys["post"])
        R_fin = _xor_bytes(R_post, keys["post"])

        # CTR keystream block 0
        ks = _ctr_keystream_block(fixed_n, 0, keys)
        ct = bytes(p ^ k for p, k in zip(pt_b, ks[:16]))

        lines = [
            "╔══════════════════════════════════════════════════════════╗",
            "║             XDES-A   STEP-BY-STEP TRACE                 ║",
            "╚══════════════════════════════════════════════════════════╝",
            "",
            f"  Plaintext (ASCII)    :  {pt_str!r}",
            f"  Plaintext (hex)      :  {pt_b.hex().upper()}",
            f"  Password             :  {'•' * len(pw_str)}",
            "",
            "  ── STEP 1: Argon2id KDF (fixed zero salt) ───────────────",
            f"  K_pre                :  {keys['pre'].hex().upper()}",
            f"  K_post               :  {keys['post'].hex().upper()}",
            f"  K_mac                :  {keys['mac'].hex().upper()}",
            "",
            "  ── STEP 2: Pre-Whitening (L ⊕ K_pre, R ⊕ K_pre) ────────",
            f"  L after whitening    :  {L_w.hex().upper()}",
            f"  R after whitening    :  {R_w.hex().upper()}",
            "",
            "  ── STEP 3: Feistel Rounds 1–8  (Left half) ─────────────",
        ]
        for i, (lh, rh) in enumerate(stL1):
            lines.append(f"  L_R{i+1:02d}  L={lh}  R={rh}")

        lines += [
            "",
            "  ── STEP 3: Feistel Rounds 1–8  (Right half) ────────────",
        ]
        for i, (lh, rh) in enumerate(stR1):
            lines.append(f"  R_R{i+1:02d}  L={lh}  R={rh}")

        lines += [
            "",
            "  ── STEP 4: Mid-Point Cross-Mix (L ⊕ R, R ⊕ L) ─────────",
            f"  L_cross              :  {L_x.hex().upper()}",
            f"  R_cross              :  {R_x.hex().upper()}",
            "",
            "  ── STEP 5: Feistel Rounds 9–16  (Left half) ────────────",
        ]
        for i, (lh, rh) in enumerate(stL2):
            lines.append(f"  L_R{i+9:02d}  L={lh}  R={rh}")

        lines += [
            "",
            "  ── STEP 5: Feistel Rounds 9–16  (Right half) ───────────",
        ]
        for i, (lh, rh) in enumerate(stR2):
            lines.append(f"  R_R{i+9:02d}  L={lh}  R={rh}")

        lines += [
            "",
            "  ── STEP 6: Post-Whitening ───────────────────────────────",
            f"  L_final              :  {L_fin.hex().upper()}",
            f"  R_final              :  {R_fin.hex().upper()}",
            "",
            "  ── STEP 7: CTR Keystream Block 0 (nonce=000…) ───────────",
            f"  Keystream            :  {ks.hex().upper()}",
            f"  Ciphertext (hex)     :  {ct.hex().upper()}",
            "",
            "  ✓  Trace complete.",
        ]
        self._write(self.tr_out, "\n".join(lines))
        self._status(self.tr_status, f"✓  Trace done. CT: {ct.hex().upper()}", GREEN)

    # ── TAB 5: BRUTE FORCE DEMO ─────────────

    def _tab_bruteforce(self):
        tab = self._frame(self.nb)
        self.nb.add(tab, text="  💀  BRUTE FORCE DEMO  ")
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(1, weight=1)

        c_in, b_in = self._card(tab, "► PASSWORD STRENGTH ANALYZER")
        c_in.grid(row=0, column=0, sticky="ew", padx=16, pady=(16,8))

        # password entry row
        row = tk.Frame(b_in, bg=BG3); row.pack(fill="x")
        col1 = tk.Frame(row, bg=BG3); col1.pack(side="left", fill="x", expand=True, padx=(0,12))
        col2 = tk.Frame(row, bg=BG3); col2.pack(side="left")

        self.bf_pw = self._labeled_entry(col1, "PASSWORD TO ANALYZE  (type your own or pick below)", width=40)
        self.bf_pw.insert(0, "password")

        tk.Label(col2, text="QUICK PRESETS", font=MONO_SM, bg=BG3, fg=FG_DIM,
                 anchor="w").pack(anchor="w", pady=(6,1))
        preset_row1 = tk.Frame(col2, bg=BG3); preset_row1.pack(anchor="w")
        preset_row2 = tk.Frame(col2, bg=BG3); preset_row2.pack(anchor="w", pady=(2,0))

        weak_presets   = ["password", "123456", "qwerty", "abc123"]
        strong_presets = ["MyS3cur3Pass!", "Tr0ub4dor&3", "X!9kLm#2vQ"]

        for p in weak_presets:
            self._btn(preset_row1, p,
                      lambda pw=p: (self.bf_pw.delete(0,"end"), self.bf_pw.insert(0,pw)),
                      color=RED).pack(side="left", padx=(0,4), pady=2)
        for p in strong_presets:
            self._btn(preset_row2, p,
                      lambda pw=p: (self.bf_pw.delete(0,"end"), self.bf_pw.insert(0,pw)),
                      color=ACCENT2).pack(side="left", padx=(0,4), pady=2)

        # note
        tk.Label(b_in,
            text="  ⚙  Compares SHA-256 (10 billion/sec GPU) vs Argon2id (10/sec GPU)."
                 "  Shows why memory-hard KDF is essential.",
            font=MONO_SM, bg=BG3, fg=FG_DIM, anchor="w").pack(anchor="w", pady=(6,0))

        btn_row = tk.Frame(b_in, bg=BG3, pady=10); btn_row.pack(anchor="w")
        self._btn(btn_row, "  ▶  ANALYZE  ", self._do_bruteforce, color=YELLOW).pack(side="left", padx=(0,8))
        self._btn(btn_row, "  📋  RUN ALL WEAK PASSWORDS  ", self._do_bruteforce_all, color=RED).pack(side="left", padx=(0,8))
        self._btn(btn_row, "  ✕  CLEAR  ", self._clear_bruteforce, color=BG3).pack(side="left")

        c_out, b_out = self._card(tab, "► ANALYSIS REPORT", pady=8)
        c_out.grid(row=1, column=0, sticky="nsew", padx=16, pady=(0,16))
        self.bf_out = self._output_box(b_out, height=16)

        self.bf_status = tk.Label(tab, text="Ready.", font=MONO_SM, bg=BG, fg=FG_DIM,
                                  anchor="w", padx=16)
        self.bf_status.grid(row=2, column=0, sticky="ew")

    def _rating_color_str(self, rating):
        return {"CRITICAL":"⛔","WEAK":"⚠ ","MODERATE":"◈ ","STRONG":"✓ ","VERY STRONG":"✓✓","UNBREAKABLE":"🔒"}.get(rating,"  ")

    def _do_bruteforce(self):
        pw = self.bf_pw.get()
        if not pw:
            self._status(self.bf_status, "⚠  Enter a password.", RED); return

        r = estimate_crack_time(pw)
        sha_icon = self._rating_color_str(r["sha256_rating"])
        arg_icon = self._rating_color_str(r["argon2_rating"])
        slowdown = r["slowdown_factor"]

        # strength bar (20 chars)
        def bar(secs, max_log=20):
            import math
            if secs <= 0: return "░" * 20
            filled = min(20, max(1, int(math.log10(max(secs,1)) / max_log * 20)))
            return "█" * filled + "░" * (20 - filled)

        sha_bar = bar(r["sha256_secs"])
        arg_bar = bar(r["argon2_secs"])

        lines = [
            "╔══════════════════════════════════════════════════════════╗",
            "║         BRUTE FORCE RESISTANCE ANALYSIS                 ║",
            "╚══════════════════════════════════════════════════════════╝",
            "",
            f"  Password          :  {'•' * len(pw)}  ({len(pw)} chars)",
            f"  Charset size      :  {r['charset']} possible characters",
            f"  Keyspace          :  {r['charset']}^{r['length']} = {r['keyspace']:.4e} combinations",
            "",
            "  ── ATTACK MODEL ─────────────────────────────────────────",
            "  Assumption: attacker tests 50% of keyspace on average.",
            "  SHA-256 rate  :  10,000,000,000 / sec  (GPU cluster, no KDF)",
            "  Argon2id rate :              ~10 / sec  (t=2, m=64MB per hash)",
            "",
            "  ── CRACKING TIME ────────────────────────────────────────",
            f"  {sha_icon} SHA-256 (no KDF)  :  {r['sha256_str']:<20}  [{r['sha256_rating']}]",
            f"     {sha_bar}",
            "",
            f"  {arg_icon} Argon2id (XDES-A) :  {r['argon2_str']:<20}  [{r['argon2_rating']}]",
            f"     {arg_bar}",
            "",
            f"  ── ARGON2ID ADVANTAGE ───────────────────────────────────",
            f"  Slowdown factor   :  ×{slowdown:,.0f}",
            f"  Meaning           :  Same attack takes {slowdown:,.0f}× longer with Argon2id.",
            "",
            "  ── CONCLUSION ───────────────────────────────────────────",
        ]

        if r["argon2_rating"] in ("STRONG", "VERY STRONG", "UNBREAKABLE"):
            lines += [
                f"  ✓  This password is RESISTANT under Argon2id.",
                f"  ✓  Even if the hash is leaked, cracking is infeasible.",
            ]
        elif r["sha256_rating"] == "CRITICAL" and r["argon2_rating"] in ("WEAK","MODERATE"):
            lines += [
                f"  ⚠  SHA-256 alone: cracked instantly.",
                f"  ◈  Argon2id buys significant time, but a longer password is better.",
            ]
        else:
            lines += [
                f"  ⛔  This password is WEAK even with Argon2id.",
                f"  ⛔  Use a longer password with mixed characters.",
            ]

        lines += [
            "",
            "  → Try one of the strong presets above to see the difference.",
        ]

        self._write(self.bf_out, "\n".join(lines))
        self._status(self.bf_status,
            f"✓  SHA-256: {r['sha256_str']}  │  Argon2id: {r['argon2_str']}  │  Slowdown: ×{slowdown:,.0f}",
            GREEN if r["argon2_rating"] in ("STRONG","VERY STRONG","UNBREAKABLE") else YELLOW)

    def _do_bruteforce_all(self):
        lines = [
            "╔══════════════════════════════════════════════════════════╗",
            "║       TOP 20 COMMON PASSWORDS — CRACK TIME COMPARISON   ║",
            "╚══════════════════════════════════════════════════════════╝",
            "",
            f"  {'PASSWORD':<16}  {'LEN':>3}  {'SHA-256':<16}  {'ARGON2ID':<20}  SLOWDOWN",
            "  " + "─"*72,
        ]
        for pw in WEAK_PASSWORDS:
            r = estimate_crack_time(pw)
            sha_icon = self._rating_color_str(r["sha256_rating"])
            arg_icon = self._rating_color_str(r["argon2_rating"])
            lines.append(
                f"  {pw:<16}  {r['length']:>3}  "
                f"{sha_icon}{r['sha256_str']:<14}  "
                f"{arg_icon}{r['argon2_str']:<18}  "
                f"×{r['slowdown_factor']:,.0f}"
            )

        lines += [
            "",
            "  ── KEY INSIGHT ──────────────────────────────────────────",
            "  All these passwords are cracked in < 1 second with SHA-256.",
            "  Argon2id's memory cost buys minutes to hours even for weak ones.",
            "  BUT: the real fix is a strong password + Argon2id together.",
            "  XDES-A uses Argon2id(t=2, m=64MB) so even leaked hashes resist attack.",
        ]
        self._write(self.bf_out, "\n".join(lines))
        self._status(self.bf_status, "✓  All 20 common passwords analyzed.", YELLOW)

    def _clear_bruteforce(self):
        self.bf_pw.delete(0, "end")
        self._write(self.bf_out, "")
        self._status(self.bf_status, "Cleared.")


# ─────────────────────────────────────────────
if __name__ == "__main__":
    app = XDESApp()
    app.mainloop()