"""
Salted-DES GUI — Tkinter Edition
Dark terminal-inspired aesthetic with monospace fonts.
"""

import os
import tkinter as tk
from tkinter import ttk, scrolledtext
import threading

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
PC1 = [
    57,49,41,33,25,17, 9, 1,58,50,42,34,26,18,
    10, 2,59,51,43,35,27,19,11, 3,60,52,44,36,
    63,55,47,39,31,23,15, 7,62,54,46,38,30,22,
    14, 6,61,53,45,37,29,21,13, 5,28,20,12, 4,
]
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
#  DES CORE
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

def left_shift(bits, n):
    return bits[n:] + bits[:n]

def generate_subkeys(key):
    key_bits = bytes_to_bits(key)
    key_pc1 = permute(key_bits, PC1)
    C, D = key_pc1[:28], key_pc1[28:]
    subkeys = []
    for shift in SHIFTS:
        C = left_shift(C, shift)
        D = left_shift(D, shift)
        subkeys.append(permute(C + D, PC2))
    return subkeys

def feistel(R, K):
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

def des_block(block, key, encrypt=True):
    subkeys = generate_subkeys(key)
    if not encrypt:
        subkeys = subkeys[::-1]
    bits = permute(bytes_to_bits(block), IP)
    L, R = bits[:32], bits[32:]
    for K in subkeys:
        L, R = R, xor_bits(L, feistel(R, K))
    return bits_to_bytes(permute(R + L, IP_INV))

def salted_des_encrypt(plaintext, key):
    salt = os.urandom(8)
    salted = bytes(p ^ s for p, s in zip(plaintext, salt))
    cipher = des_block(salted, key, encrypt=True)
    return salt, cipher, salt + cipher

def salted_des_decrypt(data, key):
    salt, cipher = data[:8], data[8:]
    salted = des_block(cipher, key, encrypt=False)
    return bytes(sp ^ s for sp, s in zip(salted, salt))

# ─────────────────────────────────────────────
#  FULL PIPELINE: Salted-DES + Caesar
#  Encrypt: Plaintext -> XOR Salt -> DES -> Caesar -> final string
#  Decrypt: Caesar^-1 -> DES^-1 -> XOR Salt -> Plaintext
# ─────────────────────────────────────────────

def pipeline_encrypt(plaintext, key, shift):
    salt, des_cipher, full = salted_des_encrypt(plaintext, key)
    hex_str = full.hex().upper()
    caesar_out = caesar_encrypt(hex_str, shift)
    return salt, des_cipher, full, caesar_out

def pipeline_decrypt(caesar_hex, key, shift):
    recovered_hex = caesar_decrypt(caesar_hex, shift)
    try:
        raw = bytes.fromhex(recovered_hex)
    except ValueError:
        raise ValueError(f"Caesar-decrypt produced invalid hex: {recovered_hex[:30]}...")
    if len(raw) != 16:
        raise ValueError(f"Expected 16 bytes after Caesar-decrypt, got {len(raw)}.")
    plaintext = salted_des_decrypt(raw, key)
    return recovered_hex, raw[:8], raw[8:], plaintext

# ─────────────────────────────────────────────
#  CAESAR CIPHER
# ─────────────────────────────────────────────

def caesar_encrypt(text, shift):
    result = []
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            result.append(ch)
    return ''.join(result)

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

def caesar_brute_force(ciphertext):
    return [(s, caesar_decrypt(ciphertext, s)) for s in range(26)]


def avalanche_analysis(plaintext, key):
    zero_salt = bytes(8)
    salted = bytes(p ^ s for p, s in zip(plaintext, zero_salt))
    base_cipher = des_block(salted, key, encrypt=True)
    results = []
    for bit_pos in range(64):
        byte_idx = bit_pos // 8
        bit_idx  = 7 - (bit_pos % 8)
        flipped = bytearray(plaintext)
        flipped[byte_idx] ^= (1 << bit_idx)
        salted_f = bytes(p ^ s for p, s in zip(bytes(flipped), zero_salt))
        fc = des_block(salted_f, key, encrypt=True)
        diff = sum(bin(x ^ y).count('1') for x, y in zip(base_cipher, fc))
        results.append(diff)
    avg = sum(results) / 64
    return avg, (avg / 64) * 100, results

# ─────────────────────────────────────────────
#  COLOR PALETTE  (dark terminal)
# ─────────────────────────────────────────────

BG       = "#0d0f14"
BG2      = "#13161d"
BG3      = "#1a1e28"
BORDER   = "#252a38"
ACCENT   = "#00e5ff"
ACCENT2  = "#7c3aed"
GREEN    = "#00ff9d"
YELLOW   = "#ffd600"
RED      = "#ff3d71"
FG       = "#cdd6f4"
FG_DIM   = "#6c7086"
MONO     = ("Courier New", 10)
MONO_SM  = ("Courier New", 9)
MONO_LG  = ("Courier New", 12, "bold")
SANS     = ("Courier New", 10)

# ─────────────────────────────────────────────
#  APP
# ─────────────────────────────────────────────

class SaltedDESApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Salted-DES  //  Modified DES Algorithm")
        self.geometry("920x700")
        self.minsize(820, 620) 
        self.configure(bg=BG)
        self.resizable(True, True)

        self._last_encrypted = None   # stores bytes for decrypt flow
        self._build_ui()

    # ── layout ──────────────────────────────

    def _build_ui(self):
        # ── header ──
        hdr = tk.Frame(self, bg=BG, pady=0)
        hdr.pack(fill="x", padx=0, pady=0)

        title_bar = tk.Frame(hdr, bg=ACCENT2, height=3)
        title_bar.pack(fill="x")

        inner_hdr = tk.Frame(hdr, bg=BG2, pady=12)
        inner_hdr.pack(fill="x")

        tk.Label(inner_hdr, text="◈  SALTED-DES", font=("Courier New", 15, "bold"),
                 bg=BG2, fg=ACCENT).pack(side="left", padx=20)
        tk.Label(inner_hdr, text="Modified Data Encryption Standard  //  IAS Case Study",
                 font=MONO_SM, bg=BG2, fg=FG_DIM).pack(side="left")

        badge = tk.Label(inner_hdr, text=" SALT + DES + CAESAR ", font=MONO_SM,
                         bg=ACCENT2, fg="white", padx=6, pady=2)
        badge.pack(side="right", padx=20)

        sep = tk.Frame(self, bg=BORDER, height=1)
        sep.pack(fill="x")

        # ── notebook (tabs) ──
        style = ttk.Style(self)
        style.theme_use("default")
        style.configure("TNotebook", background=BG, borderwidth=0, tabmargins=0)
        style.configure("TNotebook.Tab", background=BG3, foreground=FG_DIM,
                        font=MONO, padding=[16, 8], borderwidth=0)
        style.map("TNotebook.Tab",
                  background=[("selected", BG2)],
                  foreground=[("selected", ACCENT)])

        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=0, pady=0)

        self._tab_encrypt()
        self._tab_decrypt()
        self._tab_avalanche()
        self._tab_trace()
        self._tab_caesar()

    # ── helpers ─────────────────────────────

    def _frame(self, parent):
        f = tk.Frame(parent, bg=BG2)
        return f

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
        b = tk.Button(parent, text=text, font=("Courier New", 10, "bold"),
                      bg=color, fg=BG, activebackground=FG, activeforeground=BG,
                      relief="flat", bd=0, padx=18, pady=8, cursor="hand2",
                      command=cmd)
        return b

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

    def _validate_inputs(self, pt_entry, key_entry, is_bytes=False):
        pt  = pt_entry.get().strip()
        key = key_entry.get().strip()
        if not pt or not key:
            return None, None, "⚠  Both fields are required."
        if is_bytes:
            try:
                pt_b  = bytes.fromhex(pt)
                key_b = bytes.fromhex(key)
            except ValueError:
                return None, None, "⚠  Hex decode failed. Check your input."
            if len(pt_b) != 16:
                return None, None, f"⚠  Encrypted data must be 16 bytes (got {len(pt_b)})."
            if len(key_b) != 8:
                return None, None, f"⚠  Key must be exactly 8 bytes (got {len(key_b)})."
            return pt_b, key_b, None
        else:
            pt_b  = pt.encode("utf-8")
            key_b = key.encode("utf-8")
            if len(pt_b) != 8:
                return None, None, f"⚠  Plaintext must be exactly 8 bytes (got {len(pt_b)}).\n   Pad or trim to 8 ASCII chars."
            if len(key_b) != 8:
                return None, None, f"⚠  Key must be exactly 8 bytes (got {len(key_b)}).\n   Pad or trim to 8 ASCII chars."
            return pt_b, key_b, None

    # ── TAB 1: ENCRYPT ──────────────────────

    def _tab_encrypt(self):
        tab = self._frame(self.nb)
        self.nb.add(tab, text="  🔒  ENCRYPT  ")
        tab.columnconfigure(0, weight=1)
        tab.columnconfigure(1, weight=1)
        tab.rowconfigure(1, weight=1)

        # inputs
        c_in, b_in = self._card(tab, "► INPUT")
        c_in.grid(row=0, column=0, columnspan=2, sticky="ew", padx=16, pady=(16,8))

        row = tk.Frame(b_in, bg=BG3)
        row.pack(fill="x")
        col1 = tk.Frame(row, bg=BG3)
        col1.pack(side="left", fill="x", expand=True, padx=(0,8))
        col2 = tk.Frame(row, bg=BG3)
        col2.pack(side="left", fill="x", expand=True)

        self.enc_pt  = self._labeled_entry(col1, "PLAINTEXT  (8 ASCII chars)")
        self.enc_pt.insert(0, "HELLO123")
        self.enc_key = self._labeled_entry(col2, "KEY  (8 ASCII chars)")
        self.enc_key.insert(0, "SECURITY")

        col3 = tk.Frame(row, bg=BG3)
        col3.pack(side="left", padx=(8,0))
        tk.Label(col3, text="CAESAR SHIFT  (1–25)", font=MONO_SM, bg=BG3,
                 fg=FG_DIM, anchor="w").pack(anchor="w", pady=(6,1))
        self.enc_shift = tk.Spinbox(col3, from_=1, to=25, width=5,
                                    font=MONO, bg=BG, fg=YELLOW,
                                    buttonbackground=BG3, relief="flat", bd=4)
        self.enc_shift.pack(anchor="w", ipady=4)
        self.enc_shift.delete(0, "end")
        self.enc_shift.insert(0, "3")

        btn_row = tk.Frame(b_in, bg=BG3, pady=10)
        btn_row.pack(anchor="w")
        self._btn(btn_row, "  ▶  ENCRYPT  ", self._do_encrypt).pack(side="left", padx=(0,8))
        self._btn(btn_row, "  ✕  CLEAR  ", lambda: self._clear_enc(), color=BG3).pack(side="left")

        # output
        c_out, b_out = self._card(tab, "► OUTPUT", pady=8)
        c_out.grid(row=1, column=0, columnspan=2, sticky="nsew", padx=16, pady=(0,16))
        self.enc_out = self._output_box(b_out, height=12)

        # status bar
        self.enc_status = tk.Label(tab, text="Ready.", font=MONO_SM, bg=BG, fg=FG_DIM,
                                   anchor="w", padx=16)
        self.enc_status.grid(row=2, column=0, columnspan=2, sticky="ew")

    def _do_encrypt(self):
        pt_b, key_b, err = self._validate_inputs(self.enc_pt, self.enc_key)
        if err:
            self._write(self.enc_out, err)
            self.enc_status.config(text=err, fg=RED)
            return
        try:
            shift = int(self.enc_shift.get())
            if not 1 <= shift <= 25:
                raise ValueError
        except ValueError:
            self._write(self.enc_out, "⚠  Caesar shift must be 1–25.")
            self.enc_status.config(text="⚠  Invalid Caesar shift.", fg=RED)
            return

        salt, des_cipher, des_full, caesar_out = pipeline_encrypt(pt_b, key_b, shift)
        salted_pt = bytes(p ^ s for p, s in zip(pt_b, salt))

        lines = [
            "╔══════════════════════════════════════════════════════╗",
            "║         SALTED-DES + CAESAR  ENCRYPTION             ║",
            "╚══════════════════════════════════════════════════════╝",
            "",
            f"  Plaintext (ASCII)   :  {pt_b.decode()}",
            f"  Plaintext (hex)     :  {pt_b.hex().upper()}",
            f"  Key (ASCII)         :  {key_b.decode()}",
            f"  Caesar Shift        :  {shift}",
            "",
            "  ── STEP 1: SALTING ──────────────────────────────────",
            f"  Salt (random 64-bit):  {salt.hex().upper()}",
            f"  Plaintext XOR Salt  :  {salted_pt.hex().upper()}",
            "",
            "  ── STEP 2: DES (16 Feistel rounds) ─────────────────",
            f"  DES Ciphertext      :  {des_cipher.hex().upper()}",
            f"  salt || ciphertext  :  {des_full.hex().upper()}",
            "",
            "  ── STEP 3: CAESAR CIPHER (shift={}) ─────────────────".format(shift),
            f"  Input (hex string)  :  {des_full.hex().upper()}",
            f"  Caesar Output       :  {caesar_out}",
            "",
            "  ── FINAL OUTPUT ─────────────────────────────────────",
            f"  >>> {caesar_out}",
            "",
            "  ✓  Send the FINAL OUTPUT above to the DECRYPT tab.",
        ]
        self._write(self.enc_out, "\n".join(lines))
        self.enc_status.config(text=f"✓  Done. Final: {caesar_out[:32]}...", fg=GREEN)

        # auto-fill decrypt tab
        self.dec_ct.delete(0, "end")
        self.dec_ct.insert(0, caesar_out)
        self.dec_key.delete(0, "end")
        self.dec_key.insert(0, self.enc_key.get())
        self.dec_shift.delete(0, "end")
        self.dec_shift.insert(0, str(shift))

    def _clear_enc(self):
        self.enc_pt.delete(0, "end")
        self.enc_key.delete(0, "end")
        self._write(self.enc_out, "")
        self.enc_status.config(text="Cleared.", fg=FG_DIM)

    # ── TAB 2: DECRYPT ──────────────────────

    def _tab_decrypt(self):
        tab = self._frame(self.nb)
        self.nb.add(tab, text="  🔓  DECRYPT  ")
        tab.columnconfigure(0, weight=1)
        tab.columnconfigure(1, weight=1)
        tab.rowconfigure(1, weight=1)

        c_in, b_in = self._card(tab, "► INPUT")
        c_in.grid(row=0, column=0, columnspan=2, sticky="ew", padx=16, pady=(16,8))

        row = tk.Frame(b_in, bg=BG3)
        row.pack(fill="x")
        col1 = tk.Frame(row, bg=BG3)
        col1.pack(side="left", fill="x", expand=True, padx=(0,8))
        col2 = tk.Frame(row, bg=BG3)
        col2.pack(side="left", fill="x", expand=True)

        self.dec_ct  = self._labeled_entry(col1, "ENCRYPTED DATA  (Caesar output string)")
        self.dec_key = self._labeled_entry(col2, "KEY  (8 ASCII chars)")

        col3 = tk.Frame(row, bg=BG3)
        col3.pack(side="left", padx=(8,0))
        tk.Label(col3, text="CAESAR SHIFT  (1–25)", font=MONO_SM, bg=BG3,
                 fg=FG_DIM, anchor="w").pack(anchor="w", pady=(6,1))
        self.dec_shift = tk.Spinbox(col3, from_=1, to=25, width=5,
                                    font=MONO, bg=BG, fg=YELLOW,
                                    buttonbackground=BG3, relief="flat", bd=4)
        self.dec_shift.pack(anchor="w", ipady=4)
        self.dec_shift.delete(0, "end")
        self.dec_shift.insert(0, "3")

        btn_row = tk.Frame(b_in, bg=BG3, pady=10)
        btn_row.pack(anchor="w")
        self._btn(btn_row, "  ▶  DECRYPT  ", self._do_decrypt, color=GREEN).pack(side="left", padx=(0,8))
        self._btn(btn_row, "  ✕  CLEAR  ", lambda: self._clear_dec(), color=BG3).pack(side="left")

        c_out, b_out = self._card(tab, "► OUTPUT", pady=8)
        c_out.grid(row=1, column=0, columnspan=2, sticky="nsew", padx=16, pady=(0,16))
        self.dec_out = self._output_box(b_out, height=12)

        self.dec_status = tk.Label(tab, text="Ready.", font=MONO_SM, bg=BG, fg=FG_DIM,
                                   anchor="w", padx=16)
        self.dec_status.grid(row=2, column=0, columnspan=2, sticky="ew")

    def _do_decrypt(self):
        caesar_str = self.dec_ct.get().strip()
        key_str    = self.dec_key.get().strip()
        if not caesar_str or not key_str:
            self._write(self.dec_out, "⚠  Both fields are required.")
            self.dec_status.config(text="⚠  Missing inputs.", fg=RED)
            return
        key_b = key_str.encode("utf-8")
        if len(key_b) != 8:
            self._write(self.dec_out, f"⚠  Key must be exactly 8 bytes (got {len(key_b)}).")
            self.dec_status.config(text="⚠  Bad key length.", fg=RED)
            return
        try:
            shift = int(self.dec_shift.get())
            if not 1 <= shift <= 25:
                raise ValueError
        except ValueError:
            self._write(self.dec_out, "⚠  Caesar shift must be 1–25.")
            self.dec_status.config(text="⚠  Invalid shift.", fg=RED)
            return

        try:
            recovered_hex, salt, des_cipher, plaintext = pipeline_decrypt(caesar_str, key_b, shift)
            salted_pt = des_block(des_cipher, key_b, encrypt=False)

            try:
                pt_ascii = plaintext.decode("utf-8")
            except Exception:
                pt_ascii = "[non-ASCII]"

            lines = [
                "╔══════════════════════════════════════════════════════╗",
                "║         SALTED-DES + CAESAR  DECRYPTION             ║",
                "╚══════════════════════════════════════════════════════╝",
                "",
                f"  Caesar Input        :  {caesar_str}",
                f"  Key (ASCII)         :  {key_str}",
                f"  Caesar Shift        :  {shift}",
                "",
                "  ── STEP 1: CAESAR⁻¹ (shift -{}) ────────────────────".format(shift),
                f"  Recovered hex str   :  {recovered_hex}",
                "",
                "  ── STEP 2: SPLIT SALT ───────────────────────────────",
                f"  Salt                :  {salt.hex().upper()}",
                f"  DES Ciphertext      :  {des_cipher.hex().upper()}",
                "",
                "  ── STEP 3: DES DECRYPTION (subkeys reversed) ────────",
                f"  After DES-decrypt   :  {salted_pt.hex().upper()}",
                "",
                "  ── STEP 4: XOR WITH SALT ────────────────────────────",
                f"  Plaintext (hex)     :  {plaintext.hex().upper()}",
                f"  Plaintext (ASCII)   :  {pt_ascii}",
                "",
                "  ✓  D_k(E_k(m)) = m   →   PIPELINE PROOF COMPLETE",
            ]
            self._write(self.dec_out, "\n".join(lines))
            self.dec_status.config(text=f"✓  Decrypted: {pt_ascii}", fg=GREEN)

        except Exception as ex:
            self._write(self.dec_out, f"⚠  Decryption failed: {ex}")
            self.dec_status.config(text=f"⚠  Error: {ex}", fg=RED)

    def _clear_dec(self):
        self.dec_ct.delete(0, "end")
        self.dec_key.delete(0, "end")
        self._write(self.dec_out, "")
        self.dec_status.config(text="Cleared.", fg=FG_DIM)

    # ── TAB 3: AVALANCHE ────────────────────

    def _tab_avalanche(self):
        tab = self._frame(self.nb)
        self.nb.add(tab, text="  📊  AVALANCHE  ")
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(1, weight=1)

        c_in, b_in = self._card(tab, "► INPUT")
        c_in.grid(row=0, column=0, sticky="ew", padx=16, pady=(16,8))

        row = tk.Frame(b_in, bg=BG3)
        row.pack(fill="x")
        col1 = tk.Frame(row, bg=BG3)
        col1.pack(side="left", fill="x", expand=True, padx=(0,8))
        col2 = tk.Frame(row, bg=BG3)
        col2.pack(side="left", fill="x", expand=True)

        self.av_pt  = self._labeled_entry(col1, "PLAINTEXT  (8 ASCII chars)")
        self.av_pt.insert(0, "HELLO123")
        self.av_key = self._labeled_entry(col2, "KEY  (8 ASCII chars)")
        self.av_key.insert(0, "SECURITY")

        btn_row = tk.Frame(b_in, bg=BG3, pady=10)
        btn_row.pack(anchor="w")
        self._btn(btn_row, "  ▶  ANALYZE  ", self._do_avalanche, color=YELLOW).pack(side="left")

        c_out, b_out = self._card(tab, "► AVALANCHE ANALYSIS", pady=8)
        c_out.grid(row=1, column=0, sticky="nsew", padx=16, pady=(0,16))
        self.av_out = self._output_box(b_out, height=14)

        self.av_status = tk.Label(tab, text="Ready.", font=MONO_SM, bg=BG, fg=FG_DIM,
                                  anchor="w", padx=16)
        self.av_status.grid(row=2, column=0, sticky="ew")

    def _do_avalanche(self):
        pt_b, key_b, err = self._validate_inputs(self.av_pt, self.av_key)
        if err:
            self._write(self.av_out, err)
            self.av_status.config(text=err, fg=RED)
            return

        self.av_status.config(text="Running analysis (64 tests)...", fg=YELLOW)
        self.update()

        avg, pct, results = avalanche_analysis(pt_b, key_b)
        worst_val = min(results)
        best_val  = max(results)
        worst_bit = results.index(worst_val)
        best_bit  = results.index(best_val)

        # bar chart (text)
        chart_lines = []
        chart_lines.append("  BIT#  CHANGED  BAR")
        chart_lines.append("  ─────────────────────────────────────────────────────")
        for i, d in enumerate(results):
            bar = "█" * (d // 2)
            pct_i = d / 64 * 100
            flag = " ◄ WORST" if i == worst_bit else (" ◄ BEST" if i == best_bit else "")
            chart_lines.append(f"  {i:02d}    {d:02d}/64   {bar:<32} {pct_i:5.1f}%{flag}")

        lines = [
            "╔══════════════════════════════════════════════════════╗",
            "║           AVALANCHE EFFECT ANALYSIS                 ║",
            "╚══════════════════════════════════════════════════════╝",
            "",
            f"  Plaintext  :  {pt_b.hex().upper()}  ({pt_b.decode()})",
            f"  Key        :  {key_b.hex().upper()}  ({key_b.decode()})",
            f"  Bits tested:  64  (all plaintext bits, 1 flip each)",
            "",
            f"  ── SUMMARY ──────────────────────────────────────────",
            f"  Avg bits changed  :  {avg:.2f} / 64",
            f"  Avalanche %       :  {pct:.2f}%",
            f"  Ideal target      :  ~50.00%",
            f"  Result            :  {'✓ STRONG' if pct >= 45 else '⚠ WEAK'}",
            "",
            f"  Best  flip: bit {best_bit:02d}  → {best_val} bits ({best_val/64*100:.1f}%)",
            f"  Worst flip: bit {worst_bit:02d}  → {worst_val} bits ({worst_val/64*100:.1f}%)",
            "",
            "  ── PER-BIT CHART ────────────────────────────────────",
        ] + chart_lines

        self._write(self.av_out, "\n".join(lines))
        self.av_status.config(
            text=f"✓  Analysis complete. Avalanche: {pct:.2f}%",
            fg=GREEN if pct >= 45 else YELLOW
        )

    # ── TAB 4: STEP TRACE ───────────────────

    def _tab_trace(self):
        tab = self._frame(self.nb)
        self.nb.add(tab, text="  🔍  STEP TRACE  ")
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(1, weight=1)

        c_in, b_in = self._card(tab, "► INPUT")
        c_in.grid(row=0, column=0, sticky="ew", padx=16, pady=(16,8))

        row = tk.Frame(b_in, bg=BG3)
        row.pack(fill="x")
        col1 = tk.Frame(row, bg=BG3)
        col1.pack(side="left", fill="x", expand=True, padx=(0,8))
        col2 = tk.Frame(row, bg=BG3)
        col2.pack(side="left", fill="x", expand=True)

        self.tr_pt  = self._labeled_entry(col1, "PLAINTEXT  (8 ASCII chars)")
        self.tr_pt.insert(0, "HELLO123")
        self.tr_key = self._labeled_entry(col2, "KEY  (8 ASCII chars)")
        self.tr_key.insert(0, "SECURITY")

        btn_row = tk.Frame(b_in, bg=BG3, pady=10)
        btn_row.pack(anchor="w")
        self._btn(btn_row, "  ▶  TRACE ROUNDS  ", self._do_trace, color=ACCENT2).pack(side="left")

        c_out, b_out = self._card(tab, "► ROUND-BY-ROUND TRACE", pady=8)
        c_out.grid(row=1, column=0, sticky="nsew", padx=16, pady=(0,16))
        self.tr_out = self._output_box(b_out, height=14)

        self.tr_status = tk.Label(tab, text="Ready.", font=MONO_SM, bg=BG, fg=FG_DIM,
                                  anchor="w", padx=16)
        self.tr_status.grid(row=2, column=0, sticky="ew")

    def _do_trace(self):
        pt_b, key_b, err = self._validate_inputs(self.tr_pt, self.tr_key)
        if err:
            self._write(self.tr_out, err)
            self.tr_status.config(text=err, fg=RED)
            return

        # trace through with fixed salt for determinism
        salt = bytes(8)
        salted = bytes(p ^ s for p, s in zip(pt_b, salt))
        subkeys = generate_subkeys(key_b)

        bits = bytes_to_bits(salted)
        bits = permute(bits, IP)
        L, R = bits[:32], bits[32:]

        lines = [
            "╔══════════════════════════════════════════════════════╗",
            "║          SALTED-DES  ROUND-BY-ROUND TRACE           ║",
            "╚══════════════════════════════════════════════════════╝",
            "",
            f"  Plaintext (ASCII)   :  {pt_b.decode()}",
            f"  Plaintext (hex)     :  {pt_b.hex().upper()}",
            f"  Salt (fixed 0s)     :  {salt.hex().upper()}",
            f"  Salted PT (hex)     :  {salted.hex().upper()}",
            f"  Key (hex)           :  {key_b.hex().upper()}",
            "",
            "  ── AFTER INITIAL PERMUTATION (IP) ───────────────────",
            f"  L0  :  {bits_to_bytes(L).hex().upper()}",
            f"  R0  :  {bits_to_bytes(R).hex().upper()}",
            "",
            "  ── 16 FEISTEL ROUNDS ────────────────────────────────",
        ]

        for i, K in enumerate(subkeys):
            new_R = xor_bits(L, feistel(R, K))
            L, R  = R, new_R
            lines.append(
                f"  R{i+1:02d} :  {bits_to_bytes(R).hex().upper()}"
                f"   L{i+1:02d} :  {bits_to_bytes(L).hex().upper()}"
            )

        final = bits_to_bytes(permute(R + L, IP_INV))
        lines += [
            "",
            "  ── AFTER FINAL PERMUTATION (IP⁻¹) ──────────────────",
            f"  Ciphertext :  {final.hex().upper()}",
            "",
            "  ✓  Trace complete.",
        ]

        self._write(self.tr_out, "\n".join(lines))
        self.tr_status.config(text=f"✓  Trace done. Ciphertext: {final.hex().upper()}", fg=GREEN)


    # ── TAB 5: CAESAR CIPHER ────────────────

    def _tab_caesar(self):
        tab = self._frame(self.nb)
        self.nb.add(tab, text="  🔑  CAESAR  ")
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(1, weight=1)

        # ── input card ──
        c_in, b_in = self._card(tab, "► INPUT")
        c_in.grid(row=0, column=0, sticky="ew", padx=16, pady=(16,8))

        row = tk.Frame(b_in, bg=BG3)
        row.pack(fill="x")

        col1 = tk.Frame(row, bg=BG3)
        col1.pack(side="left", fill="x", expand=True, padx=(0,8))
        col2 = tk.Frame(row, bg=BG3)
        col2.pack(side="left", fill="x", expand=True, padx=(0,8))
        col3 = tk.Frame(row, bg=BG3)
        col3.pack(side="left")

        self.cs_text = self._labeled_entry(col1, "TEXT  (any length, letters only shifted)", width=30)
        self.cs_text.insert(0, "Hello World")

        tk.Label(col2, text="SHIFT  (1–25)", font=MONO_SM, bg=BG3, fg=FG_DIM,
                 anchor="w").pack(anchor="w", pady=(6,1))
        self.cs_shift = tk.Spinbox(col2, from_=1, to=25, width=6,
                                   font=MONO, bg=BG, fg=YELLOW,
                                   buttonbackground=BG3, relief="flat", bd=4)
        self.cs_shift.pack(anchor="w", ipady=4)
        self.cs_shift.delete(0, "end")
        self.cs_shift.insert(0, "3")

        tk.Label(col3, text="MODE", font=MONO_SM, bg=BG3, fg=FG_DIM,
                 anchor="w").pack(anchor="w", pady=(6,1))
        self.cs_mode = tk.StringVar(value="encrypt")
        enc_rb = tk.Radiobutton(col3, text="Encrypt", variable=self.cs_mode,
                                value="encrypt", font=MONO_SM, bg=BG3, fg=GREEN,
                                selectcolor=BG, activebackground=BG3, bd=0)
        dec_rb = tk.Radiobutton(col3, text="Decrypt", variable=self.cs_mode,
                                value="decrypt", font=MONO_SM, bg=BG3, fg=ACCENT,
                                selectcolor=BG, activebackground=BG3, bd=0)
        enc_rb.pack(anchor="w")
        dec_rb.pack(anchor="w")

        btn_row = tk.Frame(b_in, bg=BG3, pady=10)
        btn_row.pack(anchor="w")
        self._btn(btn_row, "  ▶  RUN  ", self._do_caesar, color=YELLOW).pack(side="left", padx=(0,8))
        self._btn(btn_row, "  🔓  BRUTE FORCE  ", self._do_caesar_brute, color=RED).pack(side="left", padx=(0,8))
        self._btn(btn_row, "  ✕  CLEAR  ", self._clear_caesar, color=BG3).pack(side="left")

        # ── output card ──
        c_out, b_out = self._card(tab, "► OUTPUT", pady=8)
        c_out.grid(row=1, column=0, sticky="nsew", padx=16, pady=(0,16))
        self.cs_out = self._output_box(b_out, height=14)

        self.cs_status = tk.Label(tab, text="Ready.", font=MONO_SM, bg=BG, fg=FG_DIM,
                                  anchor="w", padx=16)
        self.cs_status.grid(row=2, column=0, sticky="ew")

    def _do_caesar(self):
        text = self.cs_text.get()
        if not text:
            self.cs_status.config(text="⚠  Enter some text.", fg=RED)
            return
        try:
            shift = int(self.cs_shift.get())
            if not 1 <= shift <= 25:
                raise ValueError
        except ValueError:
            self.cs_status.config(text="⚠  Shift must be 1–25.", fg=RED)
            return

        mode = self.cs_mode.get()
        if mode == "encrypt":
            result = caesar_encrypt(text, shift)
            op = "ENCRYPT"
            color = GREEN
        else:
            result = caesar_decrypt(text, shift)
            op = "DECRYPT"
            color = ACCENT

        # per-char trace
        trace_lines = ["  CHAR  →  RESULT  (shift shown for letters)"]
        trace_lines.append("  " + "─"*40)
        for orig, res in zip(text, result):
            if orig.isalpha():
                trace_lines.append(f"    {orig!r:5}  →  {res!r:5}  (+{shift} mod 26)")
            else:
                trace_lines.append(f"    {orig!r:5}  →  {res!r:5}  (unchanged)")

        lines = [
            "╔══════════════════════════════════════════════════════╗",
            f"║               CAESAR CIPHER  {op:<24}║",
            "╚══════════════════════════════════════════════════════╝",
            "",
            f"  Input   :  {text}",
            f"  Shift   :  {shift}",
            f"  Output  :  {result}",
            "",
            "  ── CHARACTER TRACE ──────────────────────────────────",
        ] + trace_lines

        self._write(self.cs_out, "\n".join(lines))
        self.cs_status.config(text=f"✓  {op}: {result}", fg=color)

    def _do_caesar_brute(self):
        text = self.cs_text.get()
        if not text:
            self.cs_status.config(text="⚠  Enter some text to brute-force.", fg=RED)
            return

        results = caesar_brute_force(text)
        lines = [
            "╔══════════════════════════════════════════════════════╗",
            "║            CAESAR  BRUTE FORCE  (all 25 shifts)     ║",
            "╚══════════════════════════════════════════════════════╝",
            "",
            f"  Ciphertext  :  {text}",
            "",
            "  SHIFT  PLAINTEXT CANDIDATE",
            "  " + "─"*50,
        ]
        for shift, candidate in results:
            lines.append(f"  [{shift:02d}]   {candidate}")

        lines += ["", "  ↑ Scan for the readable line to find the correct shift."]
        self._write(self.cs_out, "\n".join(lines))
        self.cs_status.config(text="✓  All 25 shifts shown.", fg=YELLOW)

    def _clear_caesar(self):
        self.cs_text.delete(0, "end")
        self._write(self.cs_out, "")
        self.cs_status.config(text="Cleared.", fg=FG_DIM)


# ─────────────────────────────────────────────
if __name__ == "__main__":
    app = SaltedDESApp()
    app.mainloop()