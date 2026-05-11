

from __future__ import annotations

import itertools
import multiprocessing as mp
import time
from typing import Callable


# Force CPU-only multiprocessing (GPU code removed)
_GPU_AVAILABLE = False
_GPU_UNAVAIL_REASON = "GPU support removed; CPU-only build."  
_GPU_NAME = "CPU-only"

from cipher import (
    des_encrypt_block,
    _candidate_to_des_key,
    derive_keys,
    xdes_encrypt_block,
    BRUTE_CHARSET_ALPHA,
    BRUTE_CHARSET_ALPHANUM,
    BRUTE_CHARSET_COMMON,
)


# Hardware acceleration code removed — module is CPU-only now.


# ═══════════════════════════════════════════════════════════════════════════════
#  PUBLIC API — GPU-accelerated DES brute-force
# ═══════════════════════════════════════════════════════════════════════════════

_BATCH_SIZE = 8192   # candidates per GPU kernel launch


def brute_force_des_gpu(
    target_ct: bytes,
    known_pt: bytes,
    max_len: int,
    charset: str,
    stop_event,
    on_attempt: Callable,
    on_done: Callable,
    num_workers: int = 4,
    log_fn: Callable[[str], None] | None = None,
):
    """Brute-force DES using multiprocessing (CPU-only).

    `log_fn(text)` is an optional status callback.
    """
    def _log(msg: str):
        if log_fn:
            log_fn(msg)

    _log(f"  →  CPU-only mode — using multiprocessing ({num_workers} workers)\n\n")
    _brute_force_des_mp(target_ct, known_pt, max_len, charset,
                        stop_event, on_attempt, on_done, num_workers)


def _brute_force_des_legacy(
    target_ct, known_pt, max_len, charset,
    stop_event, on_attempt, on_done,
):
    """Legacy entrypoint kept for compatibility; runs CPU path."""
    _brute_force_des_mp(target_ct, known_pt, max_len, charset,
                        stop_event, on_attempt, on_done, num_workers=mp.cpu_count())


# Multiprocessing worker for DES

def _des_worker(args):
    """Worker: encrypts one candidate and returns (candidate, match bool)."""
    candidate, known_pt8, target_ct = args
    key8 = _candidate_to_des_key(candidate)
    ct   = des_encrypt_block(known_pt8, key8)
    return candidate, ct == target_ct


def _brute_force_des_mp(
    target_ct, known_pt, max_len, charset,
    stop_event, on_attempt, on_done, num_workers,
):
    """Multiprocessing-pool DES brute-force (CPU fallback for --no-GPU path)."""
    pt8     = (known_pt[:8] + bytes(8))[:8]
    attempt = 0
    start   = time.perf_counter()

    with mp.Pool(num_workers) as pool:
        batch = []
        for length in range(1, max_len + 1):
            for combo in itertools.product(charset, repeat=length):
                if stop_event.is_set():
                    pool.terminate()
                    on_done(False, "", attempt, time.perf_counter() - start)
                    return

                batch.append(("".join(combo), pt8, target_ct))

                if len(batch) >= _BATCH_SIZE:
                    for candidate, found in pool.imap_unordered(_des_worker, batch):
                        attempt += 1
                        elapsed  = time.perf_counter() - start
                        on_attempt(attempt, candidate, elapsed, found)
                        if found:
                            pool.terminate()
                            on_done(True, candidate, attempt, elapsed)
                            return
                    batch = []

        # flush remainder
        for candidate, found in pool.imap_unordered(_des_worker, batch):
            attempt += 1
            elapsed  = time.perf_counter() - start
            on_attempt(attempt, candidate, elapsed, found)
            if found:
                pool.terminate()
                on_done(True, candidate, attempt, elapsed)
                return

    on_done(False, "", attempt, time.perf_counter() - start)


# ═══════════════════════════════════════════════════════════════════════════════
#  PUBLIC API — GPU-accelerated XDES-A brute-force
#
# Note on GPUs for Argon2id:
# Argon2id is memory-hard: each hash needs ~64 MB of RAM. GPU threads share
# a tiny L1 cache, so running Argon2 on GPU is usually slower than CPU. Real
# crackers use the CPU path or special reduced-round variants. We use a
# multiprocessing pool (one OS process per core) to saturate CPU cores for
# the Argon2id workload.
# ═══════════════════════════════════════════════════════════════════════════════

def brute_force_xdes_gpu(
    target_ct: bytes,
    known_pt: bytes,
    argon_salt: bytes,
    max_len: int,
    charset: str,
    stop_event,
    on_attempt: Callable,
    on_done: Callable,
    num_workers: int = 4,
    log_fn: Callable[[str], None] | None = None,
):
    """XDES-A brute-force using multiprocessing (CPU-only).

    Argon2id KDF and DES rounds run on CPU workers.
    """
    def _log(msg: str):
        if log_fn:
            log_fn(msg)

    _log(f"  →  CPU-only mode — Argon2id KDF and DES run on CPU ({num_workers} workers)\n\n")
    _brute_force_xdes_mp(
        target_ct, known_pt, argon_salt, max_len, charset,
        stop_event, on_attempt, on_done, num_workers,
    )


# ── Multiprocessing worker for XDES-A ───────────────────────────────────────

def _xdes_worker(args):
    """Worker: derives Argon2id keys and encrypts one block."""
    candidate, known_pt, argon_salt, target_ct = args
    pw_b  = candidate.encode("utf-8")
    keys  = derive_keys(pw_b, argon_salt)
    pt16  = (known_pt + bytes(16))[:16]
    ct    = xdes_encrypt_block(pt16, keys)
    return candidate, ct == target_ct


def _brute_force_xdes_mp(
    target_ct, known_pt, argon_salt, max_len, charset,
    stop_event, on_attempt, on_done, num_workers,
):
    """Parallel Argon2id XDES-A brute-force using multiprocessing pool."""
    attempt = 0
    start   = time.perf_counter()

    # Argon2id is expensive so use a smaller batch to keep UI responsive
    xdes_batch = max(1, num_workers * 2)

    with mp.Pool(num_workers) as pool:
        batch = []
        for length in range(1, max_len + 1):
            for combo in itertools.product(charset, repeat=length):
                if stop_event.is_set():
                    pool.terminate()
                    on_done(False, "", attempt, time.perf_counter() - start)
                    return

                batch.append(("".join(combo), known_pt, argon_salt, target_ct))

                if len(batch) >= xdes_batch:
                    for candidate, found in pool.imap(_xdes_worker, batch):
                        attempt += 1
                        elapsed  = time.perf_counter() - start
                        on_attempt(attempt, candidate, elapsed, found)
                        if found:
                            pool.terminate()
                            on_done(True, candidate, attempt, elapsed)
                            return
                    batch = []

        for candidate, found in pool.imap(_xdes_worker, batch):
            attempt += 1
            elapsed  = time.perf_counter() - start
            on_attempt(attempt, candidate, elapsed, found)
            if found:
                pool.terminate()
                on_done(True, candidate, attempt, elapsed)
                return

    on_done(False, "", attempt, time.perf_counter() - start)


# Runtime diagnostics (CPU-only)

def verify_acceleration_setup():
    """Acceleration check removed. Prints a short message and returns False."""
    import sys
    print("\nHardware acceleration support has been removed from this module.\nUsing CPU-only multiprocessing implementation.")
    print(f"Python: {sys.version.split()[0]}, Platform: {sys.platform}")
    return False


if __name__ == "__main__":
    print("GPU support removed — running CPU-only diagnostics")
    print()
    print(f"  → Falling back to {mp.cpu_count()} CPU workers for both ciphers")
    print()
    # Quick smoke-test with a 2-char password
    import threading
    stop = threading.Event()
    results = {}

    def _on_attempt(n, c, t, found):
        if n % 100 == 0 or found:
            print(f"  [DES] #{n:>5}  trying {c!r}  {t:.2f}s", flush=True)

    def _on_done(found, candidate, n, t):
        results["found"]  = found
        results["cand"]   = candidate
        results["n"]      = n
        results["t"]      = t

    from cipher import des_encrypt_block, _candidate_to_des_key
    secret = "ab"
    pt8    = b"HELLO!!!"
    key8   = _candidate_to_des_key(secret)
    tct    = des_encrypt_block(pt8, key8)

    print(f"\n  Smoke-test: cracking DES secret {secret!r} ...")
    brute_force_des_gpu(tct, pt8, 2, "abcdefghijklmnopqrstuvwxyz",
                        stop, _on_attempt, _on_done, num_workers=4)

    if results.get("found"):
        print(f"\n  ✓  Found {results['cand']!r} in {results['n']} attempts ({results['t']:.2f}s)")
    else:
        print(f"\n  ⚠  Not found — something is wrong.")

