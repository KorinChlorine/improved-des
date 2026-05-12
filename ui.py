"""
IASSING — XDES-A Encryptor/Decryptor
Hacker terminal aesthetic. All passwords visible. Unlimited brute force length.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import time
import random
import multiprocessing as mp

from cipher import (
    xdes_a_encrypt, xdes_a_decrypt, avalanche_analysis,
    derive_keys, _xor_bytes, _feistel_half, _ctr_keystream_block,
    bytes_to_bits, bits_to_bytes, permute, xor_bits, feistel,
    IP, IP_INV, WEAK_PASSWORDS, estimate_crack_time,
    des_encrypt_block, _candidate_to_des_key, xdes_encrypt_block,
    brute_force_des, brute_force_xdes,
    BRUTE_CHARSET_ALPHA, BRUTE_CHARSET_ALPHANUM,
    BRUTE_CHARSET_COMMON, BRUTE_CHARSET_FULL,
)

# ─────────────────────────────────────────────
#  PALETTE  — phosphor green / hacker terminal
# ─────────────────────────────────────────────
BG        = "#000000"
BG2       = "#040d04"
BG3       = "#070f07"
PANEL     = "#080f08"
DIMMER    = "#050a05"
BORDER    = "#0b2b0b"
BORDER2   = "#166016"
ACCENT    = "#00ff41"
ACCENT2   = "#00cc33"
DIM       = "#004d18"
FG_DIM    = "#006622"
FG_DIMMER = "#003311"
RED       = "#ff003c"
ORANGE    = "#ff6600"
YELLOW    = "#ffe000"
CYAN      = "#00eeff"
WHITE     = "#d0ffd0"
FG        = "#00ff41"

MONO    = ("Courier New", 10)
MONO_SM = ("Courier New", 9)
MONO_LG = ("Courier New", 12, "bold")
MONO_XL = ("Courier New", 16, "bold")
MONO_XXL= ("Courier New", 19, "bold")

GLITCH_CHARS = "!@#$%^&*<>[]{}|01░▒▓"


# ─────────────────────────────────────────────
#  MATRIX RAIN
# ─────────────────────────────────────────────
class MatrixRain(tk.Canvas):
    CHARS = "01アイウエオカキクケコ#@!%&{}[]<>"

    def __init__(self, parent, width=200, height=64, **kw):
        kw.pop("width", None)
        kw.pop("height", None)
        super().__init__(parent, bg=BG, highlightthickness=0, bd=0, **kw)
        self.configure(width=width, height=height)
        self._w_px  = width
        self._h_px  = height
        self._cols  = max(1, width  // 13)
        self._rows  = max(1, height // 13)
        self._drops = [random.randint(0, self._rows) for _ in range(self._cols)]
        self._running = False
        self.bind("<Destroy>", lambda _: self.stop())

    def start(self):
        self._running = True; self._tick()

    def stop(self):
        self._running = False

    def _tick(self):
        if not self._running: return
        try:
            self.delete("all")
            for col, drop in enumerate(self._drops):
                x  = col * 13 + 6
                ch = random.choice(self.CHARS)
                fg = "#ccffcc" if random.random() > 0.9 else ACCENT
                self.create_text(x, drop*13, text=ch, fill=fg,
                                 font=("Courier New", 8, "bold"), anchor="center")
                if drop > 3:
                    self.create_text(x, (drop-3)*13, text=random.choice(self.CHARS),
                                     fill=DIM, font=("Courier New", 7), anchor="center")
                self._drops[col] = (drop + 1) % (self._rows + random.randint(0, 8))
            self.after(100, self._tick)
        except tk.TclError:
            pass


# ─────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────
def make_entry(parent, width=40, fg=ACCENT, **kw):
    wrap = tk.Frame(parent, bg=BORDER2, padx=1, pady=1)
    ent  = tk.Entry(wrap, font=MONO, bg=BG2, fg=fg,
                    insertbackground=ACCENT, relief="flat",
                    bd=5, width=width, **kw)
    ent.pack(fill="x", ipady=5)
    return wrap, ent

def make_btn(parent, text, cmd, bg=ACCENT, fg=BG):
    b = tk.Button(parent, text=text, font=("Courier New", 10, "bold"),
                  bg=bg, fg=fg, activebackground=WHITE, activeforeground=BG,
                  relief="flat", bd=0, padx=16, pady=7,
                  cursor="hand2", command=cmd)
    b.bind("<Enter>", lambda e: b.config(bg=_lighter(bg)))
    b.bind("<Leave>", lambda e: b.config(bg=bg))
    return b

def _lighter(hex_color):
    try:
        r = min(255, int(hex_color[1:3],16)+30)
        g = min(255, int(hex_color[3:5],16)+30)
        b = min(255, int(hex_color[5:7],16)+30)
        return f"#{r:02x}{g:02x}{b:02x}"
    except Exception:
        return hex_color

def make_card(parent, title="", corner="◈"):
    outer = tk.Frame(parent, bg=BORDER2, padx=1, pady=1)
    inner = tk.Frame(outer, bg=PANEL)
    inner.pack(fill="both", expand=True)
    inner.rowconfigure(1, weight=1)      
    inner.columnconfigure(0, weight=1)  
    if title:
        hdr = tk.Frame(inner, bg=DIMMER)
        hdr.pack(fill="x")
        tk.Label(hdr, text=f"  {corner}  {title}",
                 font=("Courier New", 9, "bold"),
                 bg=DIMMER, fg=ACCENT, anchor="w", pady=5).pack(side="left")
        tk.Frame(inner, bg=BORDER, height=1).pack(fill="x")
    body = tk.Frame(inner, bg=PANEL, padx=12, pady=10)
    body.pack(fill="both", expand=True)
    return outer, body

def make_output(parent, height=4):
    box = scrolledtext.ScrolledText(
        parent, font=("Courier New", 9), bg=BG2, fg=ACCENT,
        insertbackground=ACCENT, relief="flat", bd=0,
        height=height, state="disabled", wrap="none",
        selectbackground=BORDER2, selectforeground=WHITE,
    )
    box.pack(fill="both", expand=True)  
    box.tag_config("hi",   foreground=WHITE)
    box.tag_config("dim",  foreground=FG_DIM)
    box.tag_config("ok",   foreground=ACCENT)
    box.tag_config("warn", foreground=YELLOW)
    box.tag_config("err",  foreground=RED)
    box.tag_config("cyan", foreground=CYAN)
    box.tag_config("head", foreground=ACCENT, font=("Courier New",9,"bold"))
    return box

def out_clear(box):
    box.configure(state="normal"); box.delete("1.0","end")
    box.configure(state="disabled")

def out_write(box, lines):
    """lines: list of (text, tag) tuples, or a plain string."""
    box.configure(state="normal"); box.delete("1.0","end")
    if isinstance(lines, str):
        box.insert("end", lines, "ok")
    else:
        for text, tg in lines:
            box.insert("end", text, tg)
    box.configure(state="disabled"); box.see("1.0")

def out_append(box, text, tg="ok"):
    box.configure(state="normal")
    box.insert("end", text, tg)
    box.configure(state="disabled"); box.see("end")

def lbl(parent, text, fg=FG_DIM, bg=PANEL, font=None, **kw):
    return tk.Label(parent, text=text, font=font or MONO_SM,
                    bg=bg, fg=fg, anchor="w", **kw)

def statusbar(parent):
    f = tk.Frame(parent, bg=DIMMER, pady=3)
    s = tk.Label(f, text="SYS::READY", font=MONO_SM,
                 bg=DIMMER, fg=FG_DIM, anchor="w", padx=12)
    s.pack(fill="x")
    return f, s

def set_status(lbl_w, text, color=FG_DIM):
    lbl_w.config(text=text, fg=color)


# ─────────────────────────────────────────────
#  APP
# ─────────────────────────────────────────────
class XDESApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("IASSING // XDES-A  [CLASSIFIED]")
        self.geometry("1110x820")
        self.minsize(960, 700)
        self.configure(bg=BG)
        self.resizable(True, True)
        self._bf_stop    = mp.Event()
        self._bf_running = False
        self._build_header()
        self._build_tabs()
        self._glitch_loop()

    # ══════════════════════════════════════════
    #  HEADER
    # ══════════════════════════════════════════
    def _build_header(self):
        hdr = tk.Frame(self, bg=BG)
        hdr.pack(fill="x")

        self._top_bar = tk.Frame(hdr, bg=ACCENT, height=2)
        self._top_bar.pack(fill="x")

        inner = tk.Frame(hdr, bg=BG2, pady=9)
        inner.pack(fill="x")

        left = tk.Frame(inner, bg=BG2)
        left.pack(side="left", padx=18)

        self._title_lbl = tk.Label(
            left, text="█ IASSING // XDES-A",
            font=MONO_XXL, bg=BG2, fg=ACCENT)
        self._title_lbl.pack(anchor="w")

        tk.Label(left,
            text="  ARGON2ID · 128-BIT FEISTEL · CTR · HMAC-SHA256 · ACADEMIC DEMO",
            font=("Courier New", 8), bg=BG2, fg=FG_DIMMER).pack(anchor="w")

        right = tk.Frame(inner, bg=BG2)
        right.pack(side="right", padx=18)

        self._rain = MatrixRain(right, width=170, height=54)
        self._rain.place(x=0, y=0, width=170, height=54)
        right.configure(width=170, height=54)
        self._rain.start()

        tk.Label(inner,
            text="Asuncion · De Vera · Ocampo · Tesorero",
            font=("Courier New", 8), bg=BG2, fg=FG_DIMMER).pack(side="right", padx=(0,12))

        tk.Frame(self, bg=BORDER2, height=1).pack(fill="x")

    # ══════════════════════════════════════════
    #  TABS
    # ══════════════════════════════════════════
    def _build_tabs(self):
        s = ttk.Style(self)
        s.theme_use("default")
        s.configure("H.TNotebook", background=BG, borderwidth=0, tabmargins=0)
        s.configure("H.TNotebook.Tab", background=BG2, foreground=FG_DIM,
                    font=("Courier New", 9, "bold"), padding=[16, 8], borderwidth=0)
        s.map("H.TNotebook.Tab",
              background=[("selected", PANEL)],
              foreground=[("selected", ACCENT)])

        self.nb = ttk.Notebook(self, style="H.TNotebook")
        self.nb.pack(fill="both", expand=True)

        for name, builder in [
            ("  [01] ENCRYPT  ",    self._tab_encrypt),
            ("  [02] DECRYPT  ",    self._tab_decrypt),
            ("  [03] AVALANCHE ",   self._tab_avalanche),
            ("  [04] TRACE    ",    self._tab_trace),
            ("  [05] BRUTE FORCE ", self._tab_bruteforce),
        ]:
            cont, frame = self._scrollable()
            self.nb.add(cont, text=name)
            builder(frame)

    def _scrollable(self):
        cont = tk.Frame(self.nb, bg=BG)
        cont.grid_rowconfigure(0, weight=1)
        cont.grid_columnconfigure(0, weight=1)
        cvs = tk.Canvas(cont, bg=BG, highlightthickness=0, bd=0)
        sb  = tk.Scrollbar(cont, orient="vertical", command=cvs.yview)
        cvs.configure(yscrollcommand=sb.set)
        cvs.grid(row=0, column=0, sticky="nsew")
        sb.grid(row=0, column=1, sticky="ns")
        frame = tk.Frame(cvs, bg=BG)
        wid   = cvs.create_window((0,0), window=frame, anchor="nw")
        def _on_frame_configure(e):
            cvs.configure(scrollregion=cvs.bbox("all"))

        def _on_canvas_configure(e):
            cvs.itemconfig(wid, width=e.width, height=max(e.height, frame.winfo_reqheight()))

        frame.bind("<Configure>", _on_frame_configure)
        cvs.bind("<Configure>",   _on_canvas_configure)
        cvs.bind_all("<MouseWheel>",
            lambda e: cvs.yview_scroll(int(-1*(e.delta/120)), "units"))
        return cont, frame

    # ══════════════════════════════════════════
    #  TAB 01 — ENCRYPT
    # ══════════════════════════════════════════
    def _tab_encrypt(self, tab):
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(1, weight=1) 
        c, b = make_card(tab, "INPUT PARAMETERS", "[E]")
        c.grid(row=0, column=0, sticky="ew", padx=14, pady=(14,6))

        row = tk.Frame(b, bg=PANEL); row.pack(fill="x")
        c1  = tk.Frame(row, bg=PANEL); c1.pack(side="left", fill="x", expand=True, padx=(0,8))
        c2  = tk.Frame(row, bg=PANEL); c2.pack(side="left", fill="x", expand=True)

        lbl(c1, "PLAINTEXT  [ max 16 ASCII bytes ]").pack(anchor="w", pady=(0,2))
        w, self.enc_pt = make_entry(c1); w.pack(fill="x")
        self.enc_pt.insert(0, "HELLO XDES-A!!")

        lbl(c2, "PASSWORD  [ any length ]").pack(anchor="w", pady=(0,2))
        w, self.enc_pw = make_entry(c2, fg=CYAN); w.pack(fill="x")
        self.enc_pw.insert(0, "MyS3cur3Pass!")

        lbl(b, "  KDF: Argon2id(t=2,m=64MB,p=1)  │  Block: 128-bit dual-Feistel  │  CTR+HMAC-SHA256",
            fg=FG_DIMMER).pack(anchor="w", pady=(8,0))

        br = tk.Frame(b, bg=PANEL, pady=8); br.pack(anchor="w")
        make_btn(br, " ► ENCRYPT ", self._do_encrypt).pack(side="left", padx=(0,8))
        make_btn(br, " ✕ CLEAR ",   self._clear_enc, bg=DIMMER, fg=FG_DIM).pack(side="left")

        c2c, b2 = make_card(tab, "ENCRYPTION OUTPUT", "[>]")
        c2c.grid(row=1, column=0, sticky="nsew", padx=14, pady=(0,6))  
        self.enc_out = make_output(b2, height=4) 

        sf, self.enc_status = statusbar(tab)
        sf.grid(row=2, column=0, sticky="ew", padx=14, pady=(0,10))

    def _do_encrypt(self):
        pt_str = self.enc_pt.get(); pw_str = self.enc_pw.get()
        if not pt_str or not pw_str:
            out_write(self.enc_out, [("!! Both plaintext and password required.\n","err")]); return
        pt_b = pt_str.encode("utf-8")
        if len(pt_b) > 16:
            out_write(self.enc_out, [(f"!! Plaintext > 16 bytes ({len(pt_b)}).\n","err")]); return
        pt_padded = pt_b.ljust(16, b'\x00')
        set_status(self.enc_status, "SYS::KDF  Argon2id running…", YELLOW); self.update()
        try:
            argon_salt, nonce, ciphertext, tag, packet, keys = xdes_a_encrypt(pt_padded, pw_str.encode())
        except Exception as ex:
            out_write(self.enc_out, [(f"!! ENCRYPT ERROR: {ex}\n","err")])
            set_status(self.enc_status, f"SYS::ERR  {ex}", RED); return

        ph = packet.hex().upper()
        lines = [
            ("┌──────────────────────────────────────────────────────────┐\n","dim"),
            ("│          XDES-A  ::  ENCRYPTION REPORT                  │\n","head"),
            ("└──────────────────────────────────────────────────────────┘\n","dim"),
            (f"\n  PLAINTEXT  ascii  >> {pt_str!r}\n","hi"),
            (f"  PLAINTEXT  hex    >> {pt_padded.hex().upper()}\n","ok"),
            ("\n  [ STEP 1 ]  ARGON2ID KDF\n","cyan"),
            (f"  SALT (random)     >> {argon_salt.hex().upper()}\n","ok"),
            (f"  K_PRE  (whiten)   >> {keys['pre'].hex().upper()}\n","ok"),
            (f"  K_POST (whiten)   >> {keys['post'].hex().upper()}\n","ok"),
            (f"  K_MAC             >> {keys['mac'].hex().upper()}\n","ok"),
            ("  K_1..K_16         >> [16 independent 48-bit round keys]\n","dim"),
            ("\n  [ STEP 2 ]  PRE-WHITENING  (DES-X)\n","cyan"),
            (f"  L ^ K_PRE         >> {_xor_bytes(pt_padded[:8], keys['pre']).hex().upper()}\n","ok"),
            (f"  R ^ K_PRE         >> {_xor_bytes(pt_padded[8:], keys['pre']).hex().upper()}\n","ok"),
            ("\n  [ STEP 3 ]  16 FEISTEL ROUNDS  +  MID CROSS-MIX\n","cyan"),
            (f"  BLOCK OUT         >> {ciphertext.hex().upper()}\n","hi"),
            ("\n  [ STEP 4 ]  POST-WHITENING\n","cyan"),
            ("\n  [ STEP 5 ]  CTR MODE  (random nonce)\n","cyan"),
            (f"  NONCE             >> {nonce.hex().upper()}\n","ok"),
            ("\n  [ STEP 6 ]  HMAC-SHA256  (Encrypt-then-MAC)\n","cyan"),
            (f"  MAC TAG           >> {tag.hex().upper()}\n","ok"),
            ("\n  ╔════════════════════════════════════════════════════╗\n","head"),
            (f"  ║  PACKET: {ph}\n","hi"),
            ("  ╚════════════════════════════════════════════════════╝\n","head"),
            ("\n  LAYOUT: [Salt 16B][Nonce 8B][CT 16B][MAC 16B]\n","dim"),
            ("  >> Paste packet into DECRYPT tab to verify.\n","warn"),
        ]
        out_write(self.enc_out, lines)
        set_status(self.enc_status, f"SYS::OK  packet={len(packet)}B", ACCENT)
        self.dec_ct.delete(0,"end"); self.dec_ct.insert(0, ph)
        self.dec_pw.delete(0,"end"); self.dec_pw.insert(0, pw_str)

    def _clear_enc(self):
        self.enc_pt.delete(0,"end"); self.enc_pw.delete(0,"end")
        out_clear(self.enc_out); set_status(self.enc_status, "SYS::CLEARED")

    # ══════════════════════════════════════════
    #  TAB 02 — DECRYPT
    # ══════════════════════════════════════════
    def _tab_decrypt(self, tab):
        tab.columnconfigure(0, weight=1)
        c, b = make_card(tab, "INPUT PARAMETERS", "[D]")
        c.grid(row=0, column=0, sticky="ew", padx=14, pady=(14,6))

        row = tk.Frame(b, bg=PANEL); row.pack(fill="x")
        c1  = tk.Frame(row, bg=PANEL); c1.pack(side="left", fill="x", expand=True, padx=(0,8))
        c2  = tk.Frame(row, bg=PANEL); c2.pack(side="left", fill="x", expand=True)

        lbl(c1, "ENCRYPTED HEX PACKET  [ from Encrypt tab ]").pack(anchor="w", pady=(0,2))
        w, self.dec_ct = make_entry(c1); w.pack(fill="x")

        lbl(c2, "PASSWORD").pack(anchor="w", pady=(0,2))
        w, self.dec_pw = make_entry(c2, fg=CYAN); w.pack(fill="x")

        br = tk.Frame(b, bg=PANEL, pady=8); br.pack(anchor="w")
        make_btn(br, " ► DECRYPT ", self._do_decrypt, bg=ACCENT2).pack(side="left", padx=(0,8))
        make_btn(br, " ✕ CLEAR ",   self._clear_dec,  bg=DIMMER, fg=FG_DIM).pack(side="left")

        c2c, b2 = make_card(tab, "DECRYPTION OUTPUT", "[<]")
        c2c.grid(row=1, column=0, sticky="nsew", padx=14, pady=(0,6))
        tab.rowconfigure(1, weight=1)
        self.dec_out = make_output(b2, height=16)

        sf, self.dec_status = statusbar(tab)
        sf.grid(row=2, column=0, sticky="ew", padx=14, pady=(0,10))

    def _do_decrypt(self):
        hex_str = self.dec_ct.get().strip(); pw_str = self.dec_pw.get()
        if not hex_str or not pw_str:
            out_write(self.dec_out, [("!! Both fields required.\n","err")]); return
        try:
            raw = bytes.fromhex(hex_str)
        except ValueError:
            out_write(self.dec_out, [("!! Invalid hex — paste exact Encrypt output.\n","err")]); return
        set_status(self.dec_status, "SYS::KDF  Argon2id running…", YELLOW); self.update()
        try:
            argon_salt, nonce, ciphertext, tag, plaintext, keys = xdes_a_decrypt(raw, pw_str.encode())
        except Exception as ex:
            out_write(self.dec_out, [(f"!! DECRYPT ERROR: {ex}\n","err")])
            set_status(self.dec_status, f"SYS::AUTH_FAIL  {ex}", RED); return

        try:
            pt_ascii = plaintext.rstrip(b'\x00').decode("utf-8")
        except Exception:
            pt_ascii = "[non-ASCII]"

        lines = [
            ("┌──────────────────────────────────────────────────────────┐\n","dim"),
            ("│          XDES-A  ::  DECRYPTION REPORT                  │\n","head"),
            ("└──────────────────────────────────────────────────────────┘\n","dim"),
            ("\n  [ STEP 1 ]  PACKET PARSE\n","cyan"),
            (f"  SALT              >> {argon_salt.hex().upper()}\n","ok"),
            (f"  NONCE             >> {nonce.hex().upper()}\n","ok"),
            (f"  MAC (recv)        >> {tag.hex().upper()}\n","ok"),
            ("\n  [ STEP 2 ]  ARGON2ID KDF\n","cyan"),
            (f"  K_PRE             >> {keys['pre'].hex().upper()}\n","ok"),
            (f"  K_POST            >> {keys['post'].hex().upper()}\n","ok"),
            (f"  K_MAC             >> {keys['mac'].hex().upper()}\n","ok"),
            ("\n  [ STEP 3 ]  HMAC-SHA256 VERIFICATION\n","cyan"),
            ("  STATUS            >> ✓ MAC OK — INTEGRITY CONFIRMED\n","ok"),
            ("\n  [ STEP 4 ]  CTR DECRYPT → FEISTEL⁻¹ → UNWHITEN\n","cyan"),
            (f"  PLAINTEXT hex     >> {plaintext.hex().upper()}\n","ok"),
            (f"  PLAINTEXT ascii   >> {pt_ascii!r}\n","hi"),
            ("\n  ✓  D_k(E_k(m)) = m  →  PIPELINE INTEGRITY PROVEN\n","warn"),
        ]
        out_write(self.dec_out, lines)
        set_status(self.dec_status, f"SYS::DECRYPTED  >> {pt_ascii!r}", ACCENT)

    def _clear_dec(self):
        self.dec_ct.delete(0,"end"); self.dec_pw.delete(0,"end")
        out_clear(self.dec_out); set_status(self.dec_status, "SYS::CLEARED")

    # ══════════════════════════════════════════
    #  TAB 03 — AVALANCHE
    # ══════════════════════════════════════════
    def _tab_avalanche(self, tab):
        tab.columnconfigure(0, weight=1)
        c, b = make_card(tab, "AVALANCHE TEST INPUT", "[A]")
        c.grid(row=0, column=0, sticky="ew", padx=14, pady=(14,6))

        row = tk.Frame(b, bg=PANEL); row.pack(fill="x")
        c1  = tk.Frame(row, bg=PANEL); c1.pack(side="left", fill="x", expand=True, padx=(0,8))
        c2  = tk.Frame(row, bg=PANEL); c2.pack(side="left", fill="x", expand=True)

        lbl(c1, "PLAINTEXT  [ up to 16 chars ]").pack(anchor="w", pady=(0,2))
        w, self.av_pt = make_entry(c1); w.pack(fill="x")
        self.av_pt.insert(0, "HELLO XDES-A!!")
        lbl(c1, "PLAINTEXT HEX  [ up to 32 hex chars — optional, overrides text ]").pack(anchor="w", pady=(6,2))
        w, self.av_pt_hex = make_entry(c1, width=48, fg=ACCENT)
        w.pack(fill="x")

        lbl(c2, "PASSWORD").pack(anchor="w", pady=(0,2))
        w, self.av_pw = make_entry(c2, fg=CYAN); w.pack(fill="x")
        self.av_pw.insert(0, "MyS3cur3Pass!")

        lbl(b, "  Flips each of 128 plaintext bits once. KDF runs once with fixed salt=0x00*16.",
            fg=FG_DIMMER).pack(anchor="w", pady=(6,0))

        br = tk.Frame(b, bg=PANEL, pady=8); br.pack(anchor="w")
        make_btn(br, " ► ANALYZE ", self._do_avalanche, bg=YELLOW, fg=BG).pack(side="left")

        # Two-column area: left = chart/summary, right = per-iteration details
        wrapper = tk.Frame(tab, bg=BG)
        wrapper.grid(row=1, column=0, sticky="nsew", padx=14, pady=(0,6))
        wrapper.columnconfigure(0, weight=1)
        wrapper.columnconfigure(1, weight=1)
        wrapper.rowconfigure(0, weight=1)

        c_left, b_left = make_card(wrapper, "SAC ANALYSIS  [ Strict Avalanche Criterion ]", "[~]")
        c_left.grid(row=0, column=0, sticky="nsew", padx=(0,8))
        c_right, b_right = make_card(wrapper, "PER-ITERATION OUTPUT", "[>]")
        c_right.grid(row=0, column=1, sticky="nsew")

        tab.rowconfigure(1, weight=1)
        self.av_out = make_output(b_left, height=20)
        self.av_details = make_output(b_right, height=20)

        sf, self.av_status = statusbar(tab)
        sf.grid(row=2, column=0, sticky="ew", padx=14, pady=(0,10))

    def _do_avalanche(self):
        pt_hex = self.av_pt_hex.get().strip()
        pt_str = self.av_pt.get().strip()
        pw_str = self.av_pw.get()
        if not (pt_hex or pt_str) or not pw_str:
            out_write(self.av_out, [("!! Plaintext (text or hex) and password required.\n","err")]); return

        if pt_hex:
            h = pt_hex.strip()
            if h.startswith("0x") or h.startswith("0X"):
                h = h[2:]
            h = ''.join(h.split())
            try:
                pt_b = bytes.fromhex(h)
            except ValueError:
                out_write(self.av_out, [("!! Invalid hex string.\n","err")]); return
            if len(pt_b) > 16:
                out_write(self.av_out, [(f"!! Hex plaintext > 16 bytes ({len(pt_b)}).\n","err")]); return
            pt_b = pt_b.ljust(16, b'\x00')
        else:
            pt_b = pt_str.encode("utf-8")[:16].ljust(16, b'\x00')
        set_status(self.av_status, "SYS::RUNNING  KDF + 128 evaluations…", YELLOW); self.update()

        avg, pct, results, iterations = avalanche_analysis(pt_b, pw_str.encode())
        # reproduce base ciphertext (salt=0x00*16 used inside avalanche_analysis)
        keys_for_base = derive_keys(pw_str.encode(), bytes(16))
        base_ct = xdes_encrypt_block(pt_b, keys_for_base)
        worst_v = min(results); best_v = max(results)
        worst_i = results.index(worst_v); best_i  = results.index(best_v)
        verdict = "✓ STRONG — PASSES SAC" if pct >= 45 else "⚠ WEAK — FAILS SAC"

        lines = [
            ("┌──────────────────────────────────────────────────────────┐\n","dim"),
            ("│       XDES-A  ::  STRICT AVALANCHE CRITERION TEST       │\n","head"),
            ("└──────────────────────────────────────────────────────────┘\n","dim"),
            (f"\n  INPUT       >> {pt_b.hex().upper()}\n","ok"),
            (f"  BASE CT    >> {base_ct.hex().upper()}\n","ok"),
            (f"  BITS TESTED >> 128  (each bit flipped once)\n","dim"),
            ("\n  ── SUMMARY ─────────────────────────────────────────────\n","cyan"),
            (f"  AVG DELTA   >> {avg:.2f} / 128  bits changed\n","hi"),
            (f"  AVALANCHE   >> {pct:.2f}%\n","hi"),
            (f"  IDEAL       >> ~50.00%  (random oracle)\n","dim"),
            (f"  VERDICT     >> {verdict}\n","ok" if pct>=45 else "warn"),
            (f"  BEST  bit#{best_i:03d} >> {best_v}/128 changed  ({best_v/128*100:.1f}%)\n","ok"),
            (f"  WORST bit#{worst_i:03d} >> {worst_v}/128 changed  ({worst_v/128*100:.1f}%)\n","warn"),
            ("\n  ── PER-BIT CHART  [ each █ = 4 bits changed ] ──────────\n","cyan"),
            ("  BIT   DELTA   GRAPH                                  PCT\n","dim"),
            ("  " + "─"*62 + "\n","dim"),
        ]

        for i, d in enumerate(results):
            fill  = int(d/128*32)
            bar   = "█"*fill + "░"*(32-fill)
            pi    = d/128*100
            flag  = " ◄WORST" if i==worst_i else (" ◄BEST" if i==best_i else "")
            tg    = "warn" if i==worst_i else ("hi" if i==best_i else "ok")
            lines.append((f"  {i:03d}   {d:03d}/128  {bar}  {pi:5.1f}%  {flag}\n", tg))
        out_write(self.av_out, lines)

        # Write detailed per-iteration lines to the right-hand panel
        detail_lines = [("┌──────────────────────────────────────────────┐\n","dim"),
                ("│   PER-ITERATION DETAILS (bit, diff, xor, ct) │\n","head"),
                ("└──────────────────────────────────────────────┘\n","dim"),
                ("\n","dim"),
                (f"BASE CT => {base_ct.hex().upper()}\n\n","ok")]
        for it in iterations:
            b = it["bit"]
            d = it["diff"]
            xor = it["xor_hex"].upper()
            ct  = it["ct_hex"].upper()
            detail_lines.append((f"bit {b:03d} : {d:03d} bits changed\n","ok"))
            detail_lines.append((f"  XOR  => {xor}\n","dim"))
            detail_lines.append((f"  CT   => {ct}\n\n","dim"))

        out_write(self.av_details, detail_lines)
        color = ACCENT if pct>=45 else YELLOW
        set_status(self.av_status,
            f"SYS::DONE  avalanche={pct:.2f}%  {'PASS' if pct>=45 else 'FAIL'}", color)

    # ══════════════════════════════════════════
    #  TAB 04 — STEP TRACE
    # ══════════════════════════════════════════
    def _tab_trace(self, tab):
        tab.columnconfigure(0, weight=1)
        c, b = make_card(tab, "STEP TRACE INPUT", "[T]")
        c.grid(row=0, column=0, sticky="ew", padx=14, pady=(14,6))

        row = tk.Frame(b, bg=PANEL); row.pack(fill="x")
        c1  = tk.Frame(row, bg=PANEL); c1.pack(side="left", fill="x", expand=True, padx=(0,8))
        c2  = tk.Frame(row, bg=PANEL); c2.pack(side="left", fill="x", expand=True)

        lbl(c1, "PLAINTEXT  [ up to 16 chars ]").pack(anchor="w", pady=(0,2))
        w, self.tr_pt = make_entry(c1); w.pack(fill="x")
        self.tr_pt.insert(0, "HELLO XDES-A!!")

        lbl(c2, "PASSWORD").pack(anchor="w", pady=(0,2))
        w, self.tr_pw = make_entry(c2, fg=CYAN); w.pack(fill="x")
        self.tr_pw.insert(0, "MyS3cur3Pass!")

        lbl(b, "  Fixed salt=0x00*16, nonce=0x00*8 — deterministic reproducible trace.",
            fg=FG_DIMMER).pack(anchor="w", pady=(6,0))

        br = tk.Frame(b, bg=PANEL, pady=8); br.pack(anchor="w")
        make_btn(br, " ► TRACE ", self._do_trace, bg=RED, fg=WHITE).pack(side="left")

        c2c, b2 = make_card(tab, "XDES-A STEP-BY-STEP TRACE", "[↓]")
        c2c.grid(row=1, column=0, sticky="nsew", padx=14, pady=(0,6))
        tab.rowconfigure(1, weight=1)
        self.tr_out = make_output(b2, height=20)

        sf, self.tr_status = statusbar(tab)
        sf.grid(row=2, column=0, sticky="ew", padx=14, pady=(0,10))

    def _do_trace(self):
        pt_str = self.tr_pt.get(); pw_str = self.tr_pw.get()
        if not pt_str or not pw_str:
            out_write(self.tr_out, [("!! Both fields required.\n","err")]); return
        pt_b = pt_str.encode("utf-8")[:16].ljust(16, b'\x00')
        s0   = bytes(16); n0 = bytes(8)
        set_status(self.tr_status, "SYS::KDF running…", YELLOW); self.update()

        keys   = derive_keys(pw_str.encode(), s0)
        rounds = keys["rounds"]
        L_w    = _xor_bytes(pt_b[:8], keys["pre"])
        R_w    = _xor_bytes(pt_b[8:], keys["pre"])

        def trace_half(blk, subkeys):
            bits = permute(bytes_to_bits(blk), IP)
            L, R = bits[:32], bits[32:]
            st = []
            for K in subkeys:
                L, R = R, xor_bits(L, feistel(R, K))
                st.append((bits_to_bytes(L).hex().upper(), bits_to_bytes(R).hex().upper()))
            return st, bits_to_bytes(permute(R+L, IP_INV))

        stL1, Lm = trace_half(L_w, rounds[:8])
        stR1, Rm = trace_half(R_w, rounds[:8])
        Lx = _xor_bytes(Lm, Rm); Rx = _xor_bytes(Rm, Lm)
        stL2, Lp = trace_half(Lx, rounds[8:])
        stR2, Rp = trace_half(Rx, rounds[8:])
        Lf = _xor_bytes(Lp, keys["post"]); Rf = _xor_bytes(Rp, keys["post"])
        ks = _ctr_keystream_block(n0, 0, keys)
        ct = bytes(p^k for p,k in zip(pt_b, ks[:16]))

        lines = [
            ("┌──────────────────────────────────────────────────────────┐\n","dim"),
            ("│           XDES-A  ::  STEP-BY-STEP TRACE                │\n","head"),
            ("└──────────────────────────────────────────────────────────┘\n","dim"),
            (f"\n  PLAINTEXT  >> {pt_str!r}\n","hi"),
            (f"  HEX        >> {pt_b.hex().upper()}\n","ok"),
            (f"  PASSWORD   >> {pw_str}\n","cyan"),
            ("\n  [ STEP 1 ]  ARGON2ID KDF  (salt=0x00*16)\n","cyan"),
            (f"  K_PRE      >> {keys['pre'].hex().upper()}\n","ok"),
            (f"  K_POST     >> {keys['post'].hex().upper()}\n","ok"),
            (f"  K_MAC      >> {keys['mac'].hex().upper()}\n","ok"),
            ("\n  [ STEP 2 ]  PRE-WHITENING\n","cyan"),
            (f"  L^K_PRE    >> {L_w.hex().upper()}\n","ok"),
            (f"  R^K_PRE    >> {R_w.hex().upper()}\n","ok"),
            ("\n  [ STEP 3 ]  FEISTEL ROUNDS 1–8  (LEFT HALF)\n","cyan"),
        ]
        for i,(lh,rh) in enumerate(stL1):
            lines.append((f"  L_R{i+1:02d}      L={lh}  R={rh}\n","ok"))
        lines.append(("\n  [ STEP 3 ]  FEISTEL ROUNDS 1–8  (RIGHT HALF)\n","cyan"))
        for i,(lh,rh) in enumerate(stR1):
            lines.append((f"  R_R{i+1:02d}      L={lh}  R={rh}\n","ok"))
        lines += [
            ("\n  [ STEP 4 ]  MID CROSS-MIX  (L^R / R^L)\n","cyan"),
            (f"  L_cross    >> {Lx.hex().upper()}\n","hi"),
            (f"  R_cross    >> {Rx.hex().upper()}\n","hi"),
            ("\n  [ STEP 5 ]  FEISTEL ROUNDS 9–16  (LEFT HALF)\n","cyan"),
        ]
        for i,(lh,rh) in enumerate(stL2):
            lines.append((f"  L_R{i+9:02d}      L={lh}  R={rh}\n","ok"))
        lines.append(("\n  [ STEP 5 ]  FEISTEL ROUNDS 9–16  (RIGHT HALF)\n","cyan"))
        for i,(lh,rh) in enumerate(stR2):
            lines.append((f"  R_R{i+9:02d}      L={lh}  R={rh}\n","ok"))
        lines += [
            ("\n  [ STEP 6 ]  POST-WHITENING\n","cyan"),
            (f"  L_final    >> {Lf.hex().upper()}\n","hi"),
            (f"  R_final    >> {Rf.hex().upper()}\n","hi"),
            ("\n  [ STEP 7 ]  CTR KEYSTREAM  (nonce=0x00*8)\n","cyan"),
            (f"  KEYSTREAM  >> {ks.hex().upper()}\n","ok"),
            (f"  CIPHERTEXT >> {ct.hex().upper()}\n","hi"),
            ("\n  ✓  TRACE COMPLETE\n","warn"),
        ]
        out_write(self.tr_out, lines)
        set_status(self.tr_status, f"SYS::DONE  ct={ct.hex()[:16].upper()}…", ACCENT)

    # ══════════════════════════════════════════
    #  TAB 05 — BRUTE FORCE
    # ══════════════════════════════════════════
    def _tab_bruteforce(self, tab):
        tab.columnconfigure(0, weight=1)

        # ── SECTION A: Estimator ─────────────
        c, b = make_card(tab, "SECTION A  ::  PASSWORD STRENGTH ESTIMATOR", "[?]")
        c.grid(row=0, column=0, sticky="ew", padx=14, pady=(14,4))

        row = tk.Frame(b, bg=PANEL); row.pack(fill="x")
        c1  = tk.Frame(row, bg=PANEL); c1.pack(side="left", fill="x", expand=True, padx=(0,12))
        c2  = tk.Frame(row, bg=PANEL); c2.pack(side="left")

        lbl(c1, "PASSWORD TO ANALYZE").pack(anchor="w", pady=(0,2))
        w, self.bf_pw = make_entry(c1, fg=CYAN); w.pack(fill="x")
        self.bf_pw.insert(0, "password")

        lbl(c2, "QUICK PRESETS").pack(anchor="w", pady=(0,2))
        pr1 = tk.Frame(c2, bg=PANEL); pr1.pack(anchor="w")
        pr2 = tk.Frame(c2, bg=PANEL); pr2.pack(anchor="w", pady=(3,0))
        for p in ["password","123456","qwerty","abc123"]:
            make_btn(pr1, p, lambda pw=p: (self.bf_pw.delete(0,"end"), self.bf_pw.insert(0,pw)),
                     bg=RED, fg=WHITE).pack(side="left", padx=(0,3))
        for p in ["MyS3cur3Pass!","Tr0ub4dor&3","X!9kLm#2vQ"]:
            make_btn(pr2, p, lambda pw=p: (self.bf_pw.delete(0,"end"), self.bf_pw.insert(0,pw)),
                     bg=DIMMER, fg=ACCENT).pack(side="left", padx=(0,3))

        lbl(b, "  SHA-256 baseline: 10B/sec GPU  │  Argon2id: ~10/sec (t=2, m=64MB)",
            fg=FG_DIMMER).pack(anchor="w", pady=(6,0))

        br = tk.Frame(b, bg=PANEL, pady=6); br.pack(anchor="w")
        make_btn(br, " ► ANALYZE ",    self._do_estimate,   bg=YELLOW, fg=BG).pack(side="left", padx=(0,6))
        make_btn(br, " ▶▶ ALL WEAK ",  self._do_all_weak,   bg=RED, fg=WHITE).pack(side="left", padx=(0,6))
        make_btn(br, " ✕ CLEAR ",      self._clear_estimate, bg=DIMMER, fg=FG_DIM).pack(side="left")

        ce, be = make_card(tab, "ESTIMATOR OUTPUT", "[=]")
        ce.grid(row=1, column=0, sticky="ew", padx=14, pady=(0,4))
        self.bf_out = make_output(be, height=9)

        sf, self.bf_status = statusbar(tab)
        sf.grid(row=2, column=0, sticky="ew", padx=14, pady=(0,4))

        # ── SECTION B: Live Crack ─────────────
        cl, bl = make_card(tab, "SECTION B  ::  LIVE BRUTE FORCE ENGINE", "[!]")
        cl.grid(row=3, column=0, sticky="ew", padx=14, pady=(4,4))

        tk.Label(bl,
            text=(
                "  ⚠  Encrypts known plaintext, then iterates every candidate until match.\n"
                "     DES: ~thousands/sec (no KDF).  XDES-A: ~10/sec (Argon2id per guess).\n"
                "     Longer password + bigger charset = exponentially longer crack time."
            ),
            font=("Courier New", 8), bg=PANEL, fg=YELLOW,
            justify="left", anchor="w").pack(anchor="w", pady=(0,8))

        tk.Frame(bl, bg=BORDER2, height=1).pack(fill="x", pady=(0,8))

        # Config row 1
        cfg1 = tk.Frame(bl, bg=PANEL); cfg1.pack(fill="x")

        # Cipher
        cp = tk.Frame(cfg1, bg=PANEL); cp.pack(side="left", padx=(0,24))
        lbl(cp, "CIPHER").pack(anchor="w")
        self._lbf_cipher = tk.StringVar(value="des")
        for val, txt, col in [("des","DES  (fast, no KDF)",ACCENT),
                               ("xdes","XDES-A  (~10/sec)",YELLOW)]:
            tk.Radiobutton(cp, text=txt, variable=self._lbf_cipher, value=val,
                           font=MONO_SM, bg=PANEL, fg=col, selectcolor=BG2,
                           activebackground=PANEL, activeforeground=col,
                           relief="flat", bd=0).pack(anchor="w", pady=2)

        # Known plaintext
        kp = tk.Frame(cfg1, bg=PANEL); kp.pack(side="left", fill="x", expand=True, padx=(0,12))
        lbl(kp, "KNOWN PLAINTEXT  [ what we encrypt ]").pack(anchor="w")
        w, self._lbf_pt = make_entry(kp, width=16); w.pack(fill="x")
        self._lbf_pt.insert(0, "HELLO")

        # Secret — VISIBLE, no length cap
        sp = tk.Frame(cfg1, bg=PANEL); sp.pack(side="left", fill="x", expand=True)
        lbl(sp, "SECRET PASSWORD  [ VISIBLE — no length limit ]", fg=YELLOW).pack(anchor="w")
        w, self._lbf_secret = make_entry(sp, width=16, fg=RED); w.pack(fill="x")
        self._lbf_secret.insert(0, "ab")

        # Config row 2: charset | max length
        cfg2 = tk.Frame(bl, bg=PANEL); cfg2.pack(fill="x", pady=(12,0))

        csc = tk.Frame(cfg2, bg=PANEL); csc.pack(side="left", padx=(0,32))
        lbl(csc, "CHARSET").pack(anchor="w")
        self._lbf_charset = tk.StringVar(value="alpha")
        for val, txt in [("alpha","a-z              (26)"),
                         ("alphanum","a-z + 0-9        (36)"),
                         ("common","a-z + 0-9 + !@#  (39)"),
                         ("full","full printable   (94)")]:
            tk.Radiobutton(csc, text=txt, variable=self._lbf_charset, value=val,
                           font=MONO_SM, bg=PANEL, fg=FG, selectcolor=BG2,
                           activebackground=PANEL, activeforeground=ACCENT,
                           relief="flat", bd=0).pack(anchor="w")

        mlc = tk.Frame(cfg2, bg=PANEL); mlc.pack(side="left", padx=(0,32))
        lbl(mlc, "MAX SEARCH LENGTH").pack(anchor="w")
        self._lbf_maxlen = tk.StringVar(value="3")
        for v in ["1","2","3","4","5","6"]:
            tk.Radiobutton(mlc, text=f"{v} char(s)",
                           variable=self._lbf_maxlen, value=v,
                           font=MONO_SM, bg=PANEL, fg=FG, selectcolor=BG2,
                           activebackground=PANEL, activeforeground=ACCENT,
                           relief="flat", bd=0).pack(anchor="w")
        cr = tk.Frame(mlc, bg=PANEL); cr.pack(anchor="w", pady=(4,0))
        lbl(cr, "custom:").pack(side="left")
        self._lbf_custom = tk.Entry(cr, font=MONO, bg=BG2, fg=ACCENT,
                                    insertbackground=ACCENT, relief="flat", bd=3, width=5)
        self._lbf_custom.pack(side="left", padx=(4,4), ipady=3)
        make_btn(cr, "SET",
                 lambda: self._lbf_maxlen.set(self._lbf_custom.get().strip() or "3"),
                 bg=DIMMER, fg=ACCENT).pack(side="left")

        # Space estimate
        self._space_lbl = lbl(bl, "  Search space: —")
        self._space_lbl.pack(anchor="w", pady=(8,0))
        for v in (self._lbf_charset, self._lbf_maxlen):
            v.trace_add("write", self._update_space)

        # Buttons
        br2 = tk.Frame(bl, bg=PANEL, pady=8); br2.pack(anchor="w")
        self._lbf_start = make_btn(br2, " ► START CRACK ", self._do_live_bf, bg=RED, fg=WHITE)
        self._lbf_start.pack(side="left", padx=(0,8))
        self._lbf_stop  = make_btn(br2, " ■ STOP ", self._stop_live_bf, bg=ORANGE, fg=BG)
        self._lbf_stop.pack(side="left")
        self._lbf_stop.config(state="disabled")

        # Stats
        st = tk.Frame(bl, bg=PANEL); st.pack(fill="x", pady=(2,0))
        self._stat_att = lbl(st, "ATTEMPTS: —", fg=ACCENT); self._stat_att.pack(side="left", padx=(0,20))
        self._stat_rt  = lbl(st, "RATE: — /s", fg=ACCENT);  self._stat_rt.pack(side="left", padx=(0,20))
        self._stat_tm  = lbl(st, "TIME: —s",   fg=FG_DIM);  self._stat_tm.pack(side="left")

        # Live log
        clo, blo = make_card(tab, "LIVE CRACK LOG", "[LOG]")
        clo.grid(row=4, column=0, sticky="nsew", padx=14, pady=(0,14))
        tab.rowconfigure(4, weight=1)
        self._lbf_out = make_output(blo, height=12)

        sf2, self._lbf_status = statusbar(tab)
        sf2.grid(row=5, column=0, sticky="ew", padx=14, pady=(0,10))

    def _update_space(self, *_):
        m = {"alpha": BRUTE_CHARSET_ALPHA, "alphanum": BRUTE_CHARSET_ALPHANUM,
             "common": BRUTE_CHARSET_COMMON, "full": BRUTE_CHARSET_FULL}
        try:
            ml = int(self._lbf_maxlen.get())
            cs = len(m.get(self._lbf_charset.get(), BRUTE_CHARSET_ALPHA))
            total = sum(cs**l for l in range(1, ml+1))
            self._space_lbl.config(
                text=f"  Search space: ~{total:,} candidates  "
                     f"({cs}^1 + … + {cs}^{ml})")
        except Exception:
            pass

    def _rating_icon(self, r):
        return {"CRITICAL":"⛔","WEAK":"⚠","MODERATE":"◈",
                "STRONG":"✓","VERY STRONG":"✓✓","UNBREAKABLE":"🔒"}.get(r,"?")

    def _do_estimate(self):
        pw = self.bf_pw.get()
        if not pw:
            set_status(self.bf_status, "SYS::ERR  No password.", RED); return
        r  = estimate_crack_time(pw)
        si = self._rating_icon(r["sha256_rating"])
        ai = self._rating_icon(r["argon2_rating"])

        import math
        def bar(s):
            if s <= 0: return "░"*28
            n = min(28, max(1, int(math.log10(max(s,1))/20*28)))
            return "█"*n + "░"*(28-n)

        lines = [
            ("┌──────────────────────────────────────────────────────────┐\n","dim"),
            ("│        BRUTE FORCE RESISTANCE ANALYSIS                  │\n","head"),
            ("└──────────────────────────────────────────────────────────┘\n","dim"),
            (f"\n  PASSWORD   >> {pw}  (len={len(pw)})\n","hi"),
            (f"  CHARSET    >> {r['charset']} chars\n","ok"),
            (f"  KEYSPACE   >> {r['charset']}^{r['length']} = {r['keyspace']:.3e}\n","ok"),
            ("\n  ── CRACKING TIME ────────────────────────────────────────\n","cyan"),
            (f"  {si} SHA-256 (no KDF)   >> {r['sha256_str']:<20} [{r['sha256_rating']}]\n",
             "warn" if r["sha256_rating"] in ("CRITICAL","WEAK") else "ok"),
            (f"     {bar(r['sha256_secs'])}\n","dim"),
            (f"  {ai} Argon2id (XDES-A) >> {r['argon2_str']:<20} [{r['argon2_rating']}]\n",
             "ok" if r["argon2_rating"] not in ("CRITICAL","WEAK") else "warn"),
            (f"     {bar(r['argon2_secs'])}\n","dim"),
            (f"\n  SLOWDOWN FACTOR  >> x{r['slowdown_factor']:,.0f}\n","hi"),
        ]
        out_write(self.bf_out, lines)
        col = ACCENT if r["argon2_rating"] not in ("CRITICAL","WEAK") else YELLOW
        set_status(self.bf_status,
            f"SHA256={r['sha256_str']}  ARGON2={r['argon2_str']}  x{r['slowdown_factor']:,.0f}", col)

    def _do_all_weak(self):
        lines = [
            ("  PASSWORD          LEN   SHA-256          ARGON2ID             SLOWDOWN\n","cyan"),
            ("  " + "─"*72 + "\n","dim"),
        ]
        for pw in WEAK_PASSWORDS:
            r = estimate_crack_time(pw)
            si = self._rating_icon(r["sha256_rating"])
            ai = self._rating_icon(r["argon2_rating"])
            lines.append((
                f"  {pw:<18} {r['length']:>3}   {si}{r['sha256_str']:<14}   "
                f"{ai}{r['argon2_str']:<18}  x{r['slowdown_factor']:,.0f}\n","ok"))
        lines.append(("\n  >> All cracked instantly with SHA-256. "
                      "Argon2id buys time but not safety alone.\n","warn"))
        out_write(self.bf_out, lines)
        set_status(self.bf_status, "SYS::DONE  20 passwords analyzed.", YELLOW)

    def _clear_estimate(self):
        self.bf_pw.delete(0,"end"); out_clear(self.bf_out)
        set_status(self.bf_status, "SYS::CLEARED")

    def _do_live_bf(self):
        if self._bf_running: return
        pt_str     = self._lbf_pt.get().strip()
        secret     = self._lbf_secret.get().strip()
        cipher     = self._lbf_cipher.get()
        charset_id = self._lbf_charset.get()
        try:
            max_len = int(self._lbf_maxlen.get())
            if max_len < 1: raise ValueError
        except ValueError:
            out_write(self._lbf_out, [("!! Invalid max length.\n","err")]); return
        if not pt_str:
            out_write(self._lbf_out, [("!! Enter a known plaintext.\n","err")]); return
        if not secret:
            out_write(self._lbf_out, [("!! Enter a secret password.\n","err")]); return

        m = {"alpha":BRUTE_CHARSET_ALPHA,"alphanum":BRUTE_CHARSET_ALPHANUM,
             "common":BRUTE_CHARSET_COMMON,"full":BRUTE_CHARSET_FULL}
        charset = m[charset_id]
        pt_b    = pt_str.encode("utf-8")

        if cipher == "des":
            target_ct  = des_encrypt_block(pt_b[:8].ljust(8,b'\x00'),
                                            _candidate_to_des_key(secret))
            argon_salt = None
        else:
            argon_salt = bytes(16)
            keys       = derive_keys(secret.encode(), argon_salt)
            target_ct  = xdes_encrypt_block((pt_b+bytes(16))[:16], keys)

        space  = sum(len(charset)**l for l in range(1, max_len+1))
        clabel = "DES" if cipher=="des" else "XDES-A"

        hdr = [
            ("┌──────────────────────────────────────────────────────────┐\n","dim"),
            (f"│  LIVE BRUTE FORCE  //  {clabel:<36}│\n","head"),
            ("└──────────────────────────────────────────────────────────┘\n","dim"),
            (f"\n  PLAINTEXT   >> {pt_str!r}\n","ok"),
            (f"  TARGET CT   >> {target_ct.hex().upper()}\n","ok"),
            (f"  CHARSET     >> {charset_id}  ({len(charset)} chars)\n","ok"),
            (f"  MAX LEN     >> {max_len}\n","ok"),
            (f"  SPACE       >> ~{space:,} candidates\n","ok"),
            (f"  SECRET      >> {secret}  [ target — attacker searches for this ]\n","warn"),
            ("\n  ── CRACK LOG ────────────────────────────────────────────\n","cyan"),
            ("\n","ok"),
        ]
        out_write(self._lbf_out, hdr)

        if space > 5_000_000 and cipher=="xdes":
            out_append(self._lbf_out,"  ⚠  LARGE SPACE + ARGON2ID = very slow. Consider DES mode.\n","warn")
        elif space > 50_000_000:
            out_append(self._lbf_out,"  ⚠  LARGE SPACE: may take minutes.\n","warn")

        self._lbf_last_t = time.perf_counter(); self._lbf_last_n = 0
        self._bf_running = True; self._bf_stop.clear()
        self._lbf_start.config(state="disabled")
        self._lbf_stop.config(state="normal")
        set_status(self._lbf_status, f"SYS::CRACKING  {clabel}  space={space:,}", YELLOW)

        def on_attempt(attempt, candidate, elapsed, found):
            if attempt % 100 != 0 and not found: return
            now  = time.perf_counter(); dt = now - self._lbf_last_t
            rate = (attempt - self._lbf_last_n)/dt if dt > 0.02 else 0
            self._lbf_last_t = now; self._lbf_last_n = attempt
            prefix = "  ✓ FOUND  " if found else "  ···      "
            tg     = "hi" if found else "dim"
            line   = f"{prefix}#{attempt:>7}  try={candidate!r:<14}  t={elapsed:.2f}s\n"
            self.after(0, lambda l=line, t=tg: out_append(self._lbf_out, l, t))
            self.after(0, lambda: self._stat_att.config(text=f"ATTEMPTS: {attempt:,}"))
            self.after(0, lambda: self._stat_rt.config(text=f"RATE: {rate:,.0f}/s"))
            self.after(0, lambda: self._stat_tm.config(text=f"TIME: {elapsed:.1f}s"))

        def on_done(found, candidate, attempt, elapsed):
            if found:
                msg = (
                    "\n"
                    "  ╔══════════════════════════════════════════╗\n"
                    "  ║  !! SECRET CRACKED !!                    ║\n"
                    "  ╚══════════════════════════════════════════╝\n"
                    f"\n  FOUND    >> {candidate!r}\n"
                    f"  ATTEMPTS >> {attempt:,}\n"
                    f"  TIME     >> {elapsed:.3f}s\n"
                    f"  RATE     >> {attempt/max(elapsed,0.001):,.0f} /sec\n"
                )
                tg = "hi"
            else:
                msg = (
                    f"\n  ⚠  NOT FOUND in space.\n"
                    f"  Attempts={attempt:,}  Time={elapsed:.2f}s\n"
                    f"  Tip: verify charset/max-length covers the secret.\n"
                )
                tg = "warn"
            self.after(0, lambda: out_append(self._lbf_out, msg, tg))
            self.after(0, lambda: set_status(self._lbf_status,
                f"SYS::{'CRACKED' if found else 'EXHAUSTED'}  {attempt:,} in {elapsed:.2f}s",
                ACCENT if found else YELLOW))
            self.after(0, self._bf_reset)

        def run():
            try:
                if cipher=="des":
                    brute_force_des(target_ct, pt_b[:8].ljust(8,b'\x00'),
                                    max_len, charset, self._bf_stop, on_attempt, on_done)
                else:
                    brute_force_xdes(target_ct, pt_b, argon_salt,
                                     max_len, charset, self._bf_stop, on_attempt, on_done)
            except Exception as ex:
                self.after(0, lambda: out_append(self._lbf_out,f"\n  !! ERROR: {ex}\n","err"))
                self.after(0, self._bf_reset)

        threading.Thread(target=run, daemon=True).start()

    def _stop_live_bf(self):
        self._bf_stop.set()
        set_status(self._lbf_status, "SYS::STOPPING…", ORANGE)

    def _bf_reset(self):
        self._bf_running = False
        self._lbf_start.config(state="normal")
        self._lbf_stop.config(state="disabled")

    # ══════════════════════════════════════════
    #  GLITCH ANIMATION
    # ══════════════════════════════════════════
    def _glitch_loop(self):
        try:
            if random.random() < 0.07:
                glitched = "".join(
                    random.choice(GLITCH_CHARS) if (c!=" " and random.random()<0.22) else c
                    for c in "█ IASSING // XDES-A"
                )
                self._title_lbl.config(text=glitched)
                self.after(70, lambda: self._title_lbl.config(text="█ IASSING // XDES-A"))
            if random.random() < 0.04:
                self._top_bar.config(bg=RED)
                self.after(55, lambda: self._top_bar.config(bg=ACCENT))
        except tk.TclError:
            return
        self.after(350, self._glitch_loop)
