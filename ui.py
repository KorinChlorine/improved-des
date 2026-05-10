"""
IASSING Encryptor and Decryptor UI
Dark terminal-inspired aesthetic with monospace fonts.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import time
import multiprocessing as mp

from cipher import (
    xdes_a_encrypt, xdes_a_decrypt, avalanche_analysis,
    derive_keys, _xor_bytes, _feistel_half, _ctr_keystream_block,
    bytes_to_bits, bits_to_bytes, permute, xor_bits, feistel,
    IP, IP_INV, WEAK_PASSWORDS, estimate_crack_time,
    # brute force
    des_encrypt_block, _candidate_to_des_key, xdes_encrypt_block,
    brute_force_des, brute_force_xdes,
    brute_force_des_gpu, brute_force_xdes_gpu,
    BRUTE_CHARSET_ALPHA, BRUTE_CHARSET_ALPHANUM, BRUTE_CHARSET_COMMON,
)

# ─────────────────────────────────────────────
#  COLOR PALETTE  (dark terminal)
# ─────────────────────────────────────────────

BG      = "#000000"
BG2     = "#0a0e27"
BG3     = "#0f1419"
BORDER  = "#1a1f2e"
ACCENT  = "#00ff41"
ACCENT2 = "#ff0080"
GREEN   = "#39ff14"
YELLOW  = "#ffff00"
RED     = "#ff0055"
ORANGE  = "#ff6600"
FG      = "#00ff41"
FG_DIM  = "#00aa00"
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
        self.geometry("1020x760")
        self.minsize(900, 660)
        self.configure(bg=BG)
        self.resizable(True, True)
        self._bf_stop_event = mp.Event()
        self._bf_running    = False
        self._build_ui()

    # ── layout ──────────────────────────────

    def _build_ui(self):
        hdr = tk.Frame(self, bg=BG, pady=0)
        hdr.pack(fill="x")

        tk.Frame(hdr, bg=ACCENT2, height=3).pack(fill="x")

        inner_hdr = tk.Frame(hdr, bg=BG2, pady=10)
        inner_hdr.pack(fill="x")

        tk.Label(inner_hdr, text="◈  IASSING", font=("Courier New", 15, "bold"),
                 bg=BG2, fg=ACCENT).pack(side="left", padx=20)
        tk.Label(inner_hdr, text="Encryptor and Decryptor  //  XDES-A Academic Cipher",
                 font=MONO_SM, bg=BG2, fg=FG_DIM).pack(side="left")

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

    def _append(self, box, text):
        box.configure(state="normal")
        box.insert("end", text)
        box.configure(state="disabled")
        box.see("end")

    def _status(self, lbl, text, fg=FG_DIM):
        lbl.config(text=text, fg=fg)
        
    def _make_scrollable_tab(self):
        container = tk.Frame(self.nb, bg=BG)

        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        canvas = tk.Canvas(
            container,
            bg=BG,
            highlightthickness=0,
            bd=0
        )

        scrollbar = tk.Scrollbar(
            container,
            orient="vertical",
            command=canvas.yview
        )

        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")

        scroll_frame = tk.Frame(canvas, bg=BG)

        window_id = canvas.create_window(
            (0, 0),
            window=scroll_frame,
            anchor="nw"
        )

        # Update scroll region
        def on_frame_configure(event):
            canvas.configure(scrollregion=canvas.bbox("all"))

        scroll_frame.bind("<Configure>", on_frame_configure)

        # Make inner frame match canvas width
        def on_canvas_configure(event):
            canvas.itemconfig(window_id, width=event.width)

        canvas.bind("<Configure>", on_canvas_configure)

        # Mousewheel support
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        canvas.bind_all("<MouseWheel>", _on_mousewheel)

        return container, scroll_frame
    # ── TAB 1: ENCRYPT ──────────────────────

    def _tab_encrypt(self):
        tab_container, tab = self._make_scrollable_tab()
        self.nb.add(tab_container, text="  🔒  ENCRYPT  ")
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

        self.dec_ct.delete(0, "end");  self.dec_ct.insert(0, packet_hex)
        self.dec_pw.delete(0, "end");  self.dec_pw.insert(0, pw_str)

    def _clear_enc(self):
        self.enc_pt.delete(0, "end")
        self.enc_pw.delete(0, "end")
        self._write(self.enc_out, "")
        self._status(self.enc_status, "Cleared.")

    # ── TAB 2: DECRYPT ──────────────────────

    def _tab_decrypt(self):
        tab_container, tab = self._make_scrollable_tab()
        self.nb.add(tab_container, text="  🔓  DECRYPT  ")
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
        tab_container, tab = self._make_scrollable_tab()
        self.nb.add(tab_container, text="  📊  AVALANCHE  ")
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
        tab_container, tab = self._make_scrollable_tab()
        self.nb.add(tab_container, text="  🔍  STEP TRACE  ")
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
        L_w = _xor_bytes(L_raw, keys["pre"])
        R_w = _xor_bytes(R_raw, keys["pre"])
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
        L_x = _xor_bytes(L_mid, R_mid)
        R_x = _xor_bytes(R_mid, L_mid)
        stL2, L_post = trace_half(L_x, rounds[8:])
        stR2, R_post = trace_half(R_x, rounds[8:])
        L_fin = _xor_bytes(L_post, keys["post"])
        R_fin = _xor_bytes(R_post, keys["post"])
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
        lines += ["", "  ── STEP 3: Feistel Rounds 1–8  (Right half) ────────────"]
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
        lines += ["", "  ── STEP 5: Feistel Rounds 9–16  (Right half) ───────────"]
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
        tab_container, tab = self._make_scrollable_tab()
        self.nb.add(tab_container, text="  💀  BRUTE FORCE DEMO  ")
        tab.columnconfigure(0, weight=1)

        # ── Section A: Password Strength Analyzer ──
        c_est, b_est = self._card(tab, "► SECTION A — PASSWORD STRENGTH ESTIMATOR")
        c_est.grid(row=0, column=0, sticky="ew", padx=16, pady=(16,4))

        row = tk.Frame(b_est, bg=BG3); row.pack(fill="x")
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

        tk.Label(b_est,
            text="  ⚙  Compares SHA-256 (10 billion/sec GPU) vs Argon2id (10/sec GPU).",
            font=MONO_SM, bg=BG3, fg=FG_DIM, anchor="w").pack(anchor="w", pady=(6,0))

        btn_row = tk.Frame(b_est, bg=BG3, pady=8); btn_row.pack(anchor="w")
        self._btn(btn_row, "  ▶  ANALYZE  ", self._do_bruteforce, color=YELLOW).pack(side="left", padx=(0,8))
        self._btn(btn_row, "  📋  RUN ALL WEAK  ", self._do_bruteforce_all, color=RED).pack(side="left", padx=(0,8))
        self._btn(btn_row, "  ✕  CLEAR  ", self._clear_bruteforce, color=BG3).pack(side="left")

        c_out, b_out = self._card(tab, "► ESTIMATOR OUTPUT", pady=8)
        c_out.grid(row=1, column=0, sticky="ew", padx=16, pady=(0,4))
        self.bf_out = self._output_box(b_out, height=8)

        self.bf_status = tk.Label(tab, text="Ready.", font=MONO_SM, bg=BG, fg=FG_DIM,
                                  anchor="w", padx=16)
        self.bf_status.grid(row=2, column=0, sticky="ew")

        # ── Section B: Live Brute Force Engine ──
        c_lbf, b_lbf = self._card(tab, "► SECTION B — LIVE BRUTE FORCE ENGINE  (Task Manager Showcase)")
        c_lbf.grid(row=3, column=0, sticky="ew", padx=16, pady=(8,4))

        # Info banner
        info = (
            "  ⚙  Encrypts a known plaintext and brute-forces it candidate by candidate.\n"
            "     Standard DES is quick; XDES-A goes through the Argon2id path for each guess."
        )
        tk.Label(b_lbf, text=info, font=MONO_SM, bg=BG3, fg=YELLOW,
                 justify="left", anchor="w").pack(anchor="w", pady=(0,6))

        tk.Frame(b_lbf, bg=BORDER, height=1).pack(fill="x", pady=(0,8))

        # Row 1: cipher selector + known plaintext + secret password
        cfg_row = tk.Frame(b_lbf, bg=BG3); cfg_row.pack(fill="x")

        # Cipher selector
        cipher_col = tk.Frame(cfg_row, bg=BG3); cipher_col.pack(side="left", padx=(0,20))
        tk.Label(cipher_col, text="CIPHER", font=MONO_SM, bg=BG3, fg=FG_DIM).pack(anchor="w")

        self._lbf_cipher = tk.StringVar(value="xdes")
        des_rb = tk.Radiobutton(
            cipher_col, text="DES [CPU]",
            variable=self._lbf_cipher, value="des",
            font=MONO_SM, bg=BG3, fg=ACCENT, selectcolor=BG,
            activebackground=BG3, activeforeground=ACCENT,
            relief="flat", bd=0
        )
        des_rb.pack(anchor="w", pady=2)

        xdes_rb = tk.Radiobutton(
            cipher_col, text="XDES [GPU]",
            variable=self._lbf_cipher, value="xdes",
            font=MONO_SM, bg=BG3, fg=GREEN, selectcolor=BG,
            activebackground=BG3, activeforeground=GREEN,
            relief="flat", bd=0
        )
        xdes_rb.pack(anchor="w", pady=2)

        # Known plaintext
        pt_col = tk.Frame(cfg_row, bg=BG3); pt_col.pack(side="left", fill="x", expand=True, padx=(0,12))
        tk.Label(pt_col, text="KNOWN PLAINTEXT  (what we're encrypting)",
                 font=MONO_SM, bg=BG3, fg=FG_DIM, anchor="w").pack(anchor="w")
        self._lbf_pt = tk.Entry(pt_col, font=MONO, bg=BG, fg=ACCENT, insertbackground=ACCENT,
                                relief="flat", bd=6, width=20)
        self._lbf_pt.insert(0, "HELLO")
        self._lbf_pt.pack(fill="x", ipady=4)

        # Secret (what the attacker is trying to find) — VISIBLE
        sec_col = tk.Frame(cfg_row, bg=BG3); sec_col.pack(side="left", fill="x", expand=True)
        tk.Label(sec_col, text="SECRET PASSWORD  (visible  |  max 3 chars)",
                 font=MONO_SM, bg=BG3, fg=FG_DIM, anchor="w").pack(anchor="w")
        self._lbf_secret = tk.Entry(sec_col, font=MONO, bg=BG, fg=RED, insertbackground=RED,
                                    relief="flat", bd=6, width=16)
        self._lbf_secret.insert(0, "ab")
        self._lbf_secret.pack(fill="x", ipady=4)

        # Row 2: charset + max length
        cfg2_row = tk.Frame(b_lbf, bg=BG3); cfg2_row.pack(fill="x", pady=(8,0))

        cs_col = tk.Frame(cfg2_row, bg=BG3); cs_col.pack(side="left", padx=(0,24))
        tk.Label(cs_col, text="CHARSET", font=MONO_SM, bg=BG3, fg=FG_DIM).pack(anchor="w")
        self._lbf_charset = tk.StringVar(value="alpha")
        for val, label in [("alpha","a–z only (26)"), ("alphanum","a–z + 0–9 (36)"), ("common","a–z + 0–9 + !@# (39)")]:
            tk.Radiobutton(cs_col, text=label, variable=self._lbf_charset, value=val,
                           font=MONO_SM, bg=BG3, fg=FG, selectcolor=BG,
                           activebackground=BG3, activeforeground=FG,
                           relief="flat", bd=0).pack(anchor="w")

        ml_col = tk.Frame(cfg2_row, bg=BG3); ml_col.pack(side="left", padx=(0,24))
        tk.Label(ml_col, text="MAX LENGTH", font=MONO_SM, bg=BG3, fg=FG_DIM).pack(anchor="w")
        self._lbf_maxlen = tk.StringVar(value="3")
        for v in ["1","2","3"]:
            tk.Radiobutton(ml_col, text=f"Up to {v} char(s)", variable=self._lbf_maxlen, value=v,
                           font=MONO_SM, bg=BG3, fg=FG, selectcolor=BG,
                           activebackground=BG3, activeforeground=FG,
                           relief="flat", bd=0).pack(anchor="w")

        gpu_col = tk.Frame(cfg2_row, bg=BG3); gpu_col.pack(side="left")
        tk.Label(gpu_col, text="ACCELERATION", font=MONO_SM, bg=BG3, fg=FG_DIM).pack(anchor="w")
        self._lbf_use_gpu = tk.BooleanVar(value=True)
        tk.Checkbutton(gpu_col, text="Enable GPU (4 workers)", variable=self._lbf_use_gpu,
                       font=MONO_SM, bg=BG3, fg=GREEN, selectcolor=BG,
                       activebackground=BG3, activeforeground=GREEN,
                       relief="flat", bd=0).pack(anchor="w")

        # Buttons
        lbf_btn_row = tk.Frame(b_lbf, bg=BG3, pady=8); lbf_btn_row.pack(anchor="w")
        self._lbf_start_btn = self._btn(lbf_btn_row, "  ▶  START BRUTE FORCE  ", self._do_live_bf, color=RED)
        self._lbf_start_btn.pack(side="left", padx=(0,8))
        self._lbf_stop_btn  = self._btn(lbf_btn_row, "  ■  STOP  ", self._stop_live_bf, color=ORANGE)
        self._lbf_stop_btn.pack(side="left", padx=(0,8))
        self._lbf_stop_btn.config(state="disabled")

        # Live stats bar
        stats_frame = tk.Frame(b_lbf, bg=BG3); stats_frame.pack(fill="x", pady=(4,0))
        self._lbf_stat_attempt = tk.Label(stats_frame, text="Attempts: —", font=MONO_SM,
                                          bg=BG3, fg=ACCENT, width=18, anchor="w")
        self._lbf_stat_attempt.pack(side="left", padx=(0,12))
        self._lbf_stat_rate = tk.Label(stats_frame, text="Rate: — /s", font=MONO_SM,
                                       bg=BG3, fg=ACCENT, width=16, anchor="w")
        self._lbf_stat_rate.pack(side="left", padx=(0,12))
        self._lbf_stat_time = tk.Label(stats_frame, text="Time: —s", font=MONO_SM,
                                       bg=BG3, fg=FG_DIM, width=16, anchor="w")
        self._lbf_stat_time.pack(side="left")

        # Live output
        c_lbf_out, b_lbf_out = self._card(tab, "► LIVE BRUTE FORCE LOG", pady=6)
        c_lbf_out.grid(row=4, column=0, sticky="nsew", padx=16, pady=(0,16))
        tab.rowconfigure(4, weight=1)
        self._lbf_out = self._output_box(b_lbf_out, height=10)

        self._lbf_status = tk.Label(tab, text="Ready. Configure above and press START.",
                                    font=MONO_SM, bg=BG, fg=FG_DIM, anchor="w", padx=16)
        self._lbf_status.grid(row=5, column=0, sticky="ew")

    # ── brute force estimator helpers ───────

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
            "  ── ARGON2ID ADVANTAGE ───────────────────────────────────",
            f"  Slowdown factor   :  ×{slowdown:,.0f}",
            f"  Meaning           :  Same attack takes {slowdown:,.0f}× longer with Argon2id.",
            "",
            "  ── CONCLUSION ───────────────────────────────────────────",
        ]

        if r["argon2_rating"] in ("STRONG", "VERY STRONG", "UNBREAKABLE"):
            lines += [
                "  ✓  This password is RESISTANT under Argon2id.",
                "  ✓  Even if the hash is leaked, cracking is infeasible.",
            ]
        elif r["sha256_rating"] == "CRITICAL" and r["argon2_rating"] in ("WEAK","MODERATE"):
            lines += [
                "  ⚠  SHA-256 alone: cracked instantly.",
                "  ◈  Argon2id buys significant time, but a longer password is better.",
            ]
        else:
            lines += [
                "  ⛔  This password is WEAK even with Argon2id.",
                "  ⛔  Use a longer password with mixed characters.",
            ]

        lines += ["", "  → Try one of the strong presets above to see the difference."]
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

    # ── live brute force engine ──────────────

    def _do_live_bf(self):
        if self._bf_running:
            return

        pt_str     = self._lbf_pt.get().strip()
        secret     = self._lbf_secret.get().strip()
        cipher     = self._lbf_cipher.get()
        charset_id = self._lbf_charset.get()
        max_len    = int(self._lbf_maxlen.get())

        if not pt_str:
            self._write(self._lbf_out, "⚠  Enter a known plaintext.")
            return
        if not secret:
            self._write(self._lbf_out, "⚠  Enter a secret to brute-force.")
            return
        if len(secret) > 4:
            self._write(self._lbf_out, "⚠  Secret must be ≤ 4 characters for a live demo.")
            return

        charset_map = {
            "alpha":    BRUTE_CHARSET_ALPHA,
            "alphanum": BRUTE_CHARSET_ALPHANUM,
            "common":   BRUTE_CHARSET_COMMON,
        }
        charset = charset_map[charset_id]

        # Pre-compute target ciphertext so attacker has something to match against
        pt_b = pt_str.encode("utf-8")

        if cipher == "des":
            key8      = _candidate_to_des_key(secret)
            target_ct = des_encrypt_block(pt_b[:8].ljust(8, b'\x00'), key8)
            argon_salt = None
        else:
            argon_salt = bytes(16)   # fixed zero salt for demo repeatability
            keys       = derive_keys(secret.encode(), argon_salt)
            pt16       = (pt_b + bytes(16))[:16]
            target_ct  = xdes_encrypt_block(pt16, keys)

        cipher_label = "Standard DES" if cipher == "des" else "XDES-A (Argon2id)"
        accel_label = "[GPU]" if self._lbf_use_gpu.get() else "[CPU]"

        header = [
            "╔══════════════════════════════════════════════════════════╗",
            f"║  LIVE BRUTE FORCE  —  {cipher_label:<22} {accel_label:<10}║",
            "╚══════════════════════════════════════════════════════════╝",
            "",
            f"  Known plaintext  :  {pt_str!r}",
            f"  Target ciphertext:  {target_ct.hex().upper()}",
            f"  Charset          :  {charset_id}  ({len(charset)} chars)",
            f"  Max length       :  {max_len}",
            f"  Secret (hidden)  :  {'•' * len(secret)}",
            "",
            f"  ── LIVE LOG ─────────────────────────────────────────────",
            "",
        ]
        self._write(self._lbf_out, "\n".join(header))

        # Rate tracking
        self._lbf_last_update = time.perf_counter()
        self._lbf_last_count  = 0

        self._bf_running = True
        self._bf_stop_event.clear()
        self._lbf_start_btn.config(state="disabled")
        self._lbf_stop_btn.config(state="normal")
        gpu_status = "GPU ACCELERATED" if self._lbf_use_gpu.get() else "CPU SINGLE-THREAD"
        self._status(self._lbf_status, f"⏳  [{gpu_status}] Cracking...  ", YELLOW)

        def on_attempt(attempt, candidate, elapsed, found):
            # Throttle UI updates to every 50 attempts or on find
            if attempt % 50 != 0 and not found:
                return

            now  = time.perf_counter()
            dt   = now - self._lbf_last_update
            rate = (attempt - self._lbf_last_count) / dt if dt > 0.01 else 0
            self._lbf_last_update = now
            self._lbf_last_count  = attempt

            prefix = "  ✓  FOUND! " if found else "  ···  "
            line   = f"{prefix}[#{attempt:>6}]  trying: {candidate!r:<8}  " \
                     f"elapsed: {elapsed:6.2f}s\n"

            self.after(0, lambda l=line: self._append(self._lbf_out, l))
            self.after(0, lambda: self._lbf_stat_attempt.config(text=f"Attempts: {attempt:,}"))
            self.after(0, lambda: self._lbf_stat_rate.config(text=f"Rate: {rate:,.0f}/s"))
            self.after(0, lambda: self._lbf_stat_time.config(text=f"Time: {elapsed:.1f}s"))

        def on_done(found, candidate, attempt, elapsed):
            if found:
                summary = (
                    f"\n"
                    f"  ╔══════════════════════════════════╗\n"
                    f"  ║  🔓  SECRET CRACKED!             ║\n"
                    f"  ╚══════════════════════════════════╝\n"
                    f"\n"
                    f"  Found: {candidate!r}\n"
                    f"  Attempts : {attempt:,}\n"
                    f"  Time     : {elapsed:.2f}s\n"
                    f"  Avg rate : {attempt/max(elapsed,0.001):,.0f} attempts/sec\n"
                )
            else:
                summary = (
                    f"\n"
                    f"  ⚠  Secret not found in search space.\n"
                    f"  Attempts: {attempt:,}  Time: {elapsed:.2f}s\n"
                )
            self.after(0, lambda: self._append(self._lbf_out, summary))
            self.after(0, lambda: self._status(
                self._lbf_status,
                f"✓  Done — {attempt:,} attempts in {elapsed:.2f}",
                GREEN if found else YELLOW))
            self.after(0, self._bf_reset_buttons)

        def run():
            try:
                use_gpu = self._lbf_use_gpu.get()
                if cipher == "des":
                    if use_gpu:
                        brute_force_des_gpu(
                            target_ct, pt_b[:8].ljust(8, b'\x00'),
                            max_len, charset,
                            self._bf_stop_event, on_attempt, on_done, num_workers=4
                        )
                    else:
                        brute_force_des(
                            target_ct, pt_b[:8].ljust(8, b'\x00'),
                            max_len, charset,
                            self._bf_stop_event, on_attempt, on_done,
                        )
                else:
                    if use_gpu:
                        brute_force_xdes_gpu(
                            target_ct, pt_b,
                            argon_salt,
                            max_len, charset,
                            self._bf_stop_event, on_attempt, on_done, num_workers=4
                        )
                    else:
                        brute_force_xdes(
                            target_ct, pt_b,
                            argon_salt,
                            max_len, charset,
                            self._bf_stop_event, on_attempt, on_done,
                        )
            except Exception as ex:
                self.after(0, lambda: self._append(self._lbf_out, f"\n  ⚠  Error: {ex}\n"))
                self.after(0, self._bf_reset_buttons)

        t = threading.Thread(target=run, daemon=True)
        t.start()

    def _stop_live_bf(self):
        self._bf_stop_event.set()
        self._status(self._lbf_status, "⏹  Stopping…", ORANGE)

    def _bf_reset_buttons(self):
        self._bf_running = False
        self._lbf_start_btn.config(state="normal")
        self._lbf_stop_btn.config(state="disabled")


if __name__ == "__main__":
    app = XDESApp()
    app.mainloop()