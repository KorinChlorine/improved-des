"""
XDES-A Cipher Implementation
Argon2id KDF → Independent round keys → 128-bit block (dual 64-bit Feistel)
Pre/Post Whitening (DES-X) → CTR Mode → HMAC-SHA256 (Encrypt-then-MAC)
"""

import os                          # For generating random bytes (salt, nonce)
import hmac                        # For computing HMAC-SHA256 authentication tags
import hashlib                     # For SHA256 hashing
import struct                      # For packing/unpacking binary data
import time                        # For measuring performance
import itertools                   # For generating candidate passwords
from argon2.low_level import hash_secret_raw, Type  # Argon2id password hashing (secure KDF)

# ═════════════════════════════════════════════════════════════════════════════
#  DES TABLES (Standard DES permutation and transformation tables)
# ═════════════════════════════════════════════════════════════════════════════
# These tables define how bits are rearranged in the DES algorithm:
#   IP/IP_INV  = Initial/final permutation (bit reordering)
#   E          = Expansion permutation (32 bits → 48 bits)
#   P          = Bit permutation after S-box substitution
#   PC1_C/PC1_D = Key permutation for key schedule generation
#   PC2        = Compression permutation for round key selection
#   S_BOXES    = Substitution tables (the core nonlinearity in DES)
#   SHIFTS     = Bit rotation amounts for key schedule

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

# ═════════════════════════════════════════════════════════════════════════════
#  DES BIT PRIMITIVES (Low-level bit manipulation functions)
# ═════════════════════════════════════════════════════════════════════════════
# These functions handle the bit-level operations required by DES

def bytes_to_bits(b):
    """Convert bytes to a list of individual bits (0 or 1) for DES operations."""
    bits = []
    for byte in b:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits

def bits_to_bytes(bits):
    """Convert a list of bits back to bytes (inverse of bytes_to_bits)."""
    result = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        result.append(byte)
    return bytes(result)

def permute(bits, table):
    """Rearrange bits according to a permutation table (used throughout DES)."""
    return [bits[t - 1] for t in table]

def xor_bits(a, b):
    """Bitwise XOR two bit sequences (core operation of symmetric encryption)."""
    return [x ^ y for x, y in zip(a, b)]

def feistel(R, K):
    """Perform one Feistel round function: expand 32 bits to 48, XOR with key, apply S-boxes."""
    expanded = permute(R, E)  # Expand right half from 32 bits to 48 bits
    xored = xor_bits(expanded, K)  # XOR with round key
    # Apply S-box substitutions (split 48 bits into 8 groups of 6, each group -> 4 bits)
    sbox_out = []
    for i in range(8):
        chunk = xored[i*6:(i+1)*6]  # Extract 6 bits for this S-box
        row = (chunk[0] << 1) | chunk[5]      # Row index from first and last bit
        col = (chunk[1] << 3) | (chunk[2] << 2) | (chunk[3] << 1) | chunk[4]  # Column index
        val = S_BOXES[i][row][col]  # Lookup substitution value (0-15)
        for b in range(3, -1, -1):
            sbox_out.append((val >> b) & 1)  # Convert to 4 bits
    return permute(sbox_out, P)  # Apply final bit permutation

# ═════════════════════════════════════════════════════════════════════════════
#  STANDARD DES KEY SCHEDULE (Generate 16 round keys from 8-byte master key)
# ═════════════════════════════════════════════════════════════════════════════
# Takes an 8-byte key and produces 16 48-bit round keys through permutations and rotations

def des_key_schedule(key_8bytes: bytes) -> list:
    """Generate 16 round keys from a single 8-byte master key."""
    """Generate 16 round keys from a single 8-byte master key."""
    key_bits = bytes_to_bits(key_8bytes)  # Convert key to 64 bits
    # Split key using parity-check bit removal (PC1 permutation)
    C = [key_bits[b - 1] for b in PC1_C]  # Left half (28 bits)
    D = [key_bits[b - 1] for b in PC1_D]  # Right half (28 bits)
    round_keys = []
    # For each of 16 rounds: rotate halves and extract round key
    for shift in SHIFTS:
        C = C[shift:] + C[:shift]  # Rotate left half
        D = D[shift:] + D[:shift]  # Rotate right half
        CD = C + D  # Combine halves
        k48 = [CD[b - 1] for b in PC2]  # Apply compression to get 48-bit round key
        round_keys.append(k48)
    return round_keys

# ═════════════════════════════════════════════════════════════════════════════
#  STANDARD DES BLOCK ENCRYPT/DECRYPT (Classic 8-byte block DES)
# ═════════════════════════════════════════════════════════════════════════════
# Standard DES operates on 8-byte blocks and uses 8-byte keys

def des_encrypt_block(block_8: bytes, key_8: bytes) -> bytes:
    """Encrypt an 8-byte block using standard DES (64-bit block, 56-bit key)."""
    """Encrypt an 8-byte block using standard DES (64-bit block, 56-bit key)."""
    round_keys = des_key_schedule(key_8)  # Generate 16 round keys
    bits = permute(bytes_to_bits(block_8), IP)  # Apply initial permutation
    L, R = bits[:32], bits[32:]  # Split into left and right halves
    # Execute 16 Feistel rounds
    for K in round_keys:
        L, R = R, xor_bits(L, feistel(R, K))  # Standard Feistel operation
    return bits_to_bytes(permute(R + L, IP_INV))  # Combine and apply final permutation

def des_decrypt_block(block_8: bytes, key_8: bytes) -> bytes:
    """Decrypt an 8-byte block using standard DES (just use round keys in reverse)."""
    round_keys = list(reversed(des_key_schedule(key_8)))  # Reverse order of round keys
    bits = permute(bytes_to_bits(block_8), IP)  # Apply initial permutation
    L, R = bits[:32], bits[32:]  # Split into halves
    # Execute 16 Feistel rounds in reverse order
    for K in round_keys:
        L, R = R, xor_bits(L, feistel(R, K))
    return bits_to_bytes(permute(R + L, IP_INV))  # Combine and apply final permutation

# ═════════════════════════════════════════════════════════════════════════════
#  XDES-A KEY DERIVATION using Argon2id (Memory-hard KDF)
# ═════════════════════════════════════════════════════════════════════════════
# Argon2id is a secure password hashing algorithm resistant to GPU/ASIC attacks.
# We derive multiple keys from password: pre-whitening, 16 round keys, post-whitening, MAC key

KDF_TOTAL  = 8 + 112 + 8 + 24   # 152 bytes total: 8 (pre) + 112 (16 keys × 7) + 8 (post) + 24 (MAC)
ARGON2_T   = 2       # Time cost (2 iterations)
ARGON2_M   = 65536   # Memory cost (64 MB)
ARGON2_P   = 1       # Parallelism (1 thread)

def derive_keys(password: bytes, salt: bytes) -> dict:
    """Derive cryptographic keys from password using Argon2id KDF.
    Returns: dict with pre-whitening key, 16 round keys, post-whitening key, and MAC key.
    """
    """Derive cryptographic keys from password using Argon2id KDF.
    Returns: dict with pre-whitening key, 16 round keys, post-whitening key, and MAC key.
    """
    # Use Argon2id to derive 152 bytes from password and salt
    raw = hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=ARGON2_T,
        memory_cost=ARGON2_M,
        parallelism=ARGON2_P,
        hash_len=KDF_TOTAL,
        type=Type.ID,  # Type.ID = Argon2id (hybrid GPU/memory resistant)
    )
    # Split raw key material into components
    k_pre        = raw[0:8]        # 8-byte pre-whitening key
    k_rounds_raw = raw[8:120]      # 112 bytes for 16 round keys (7 bytes each)
    k_post       = raw[120:128]    # 8-byte post-whitening key
    k_mac        = raw[128:152]    # 24-byte HMAC-SHA256 key

    # Convert each 7-byte chunk into a 48-bit DES round key
    round_keys = []
    for i in range(16):
        chunk   = k_rounds_raw[i*7:(i+1)*7]  # Extract 7 bytes
        padded  = chunk + bytes(1)             # Pad to 8 bytes
        bits_56 = bytes_to_bits(padded)[:56]  # Convert to 56 bits (drop parity bits)
        k48     = permute(bits_56, PC2)        # Apply DES compression to get 48-bit key
        round_keys.append(k48)

    return {
        "pre":    k_pre,       # Pre-whitening (XOR before encryption)
        "rounds": round_keys,  # 16 DES round keys
        "post":   k_post,      # Post-whitening (XOR after encryption)
        "mac":    k_mac,       # HMAC-SHA256 key for authentication tag
        "raw":    raw,         # Full 152 bytes (for debugging)
    }

# ═════════════════════════════════════════════════════════════════════════════
#  XDES-A BLOCK CIPHER (128-bit blocks, improved DES with dual Feistel)
# ═════════════════════════════════════════════════════════════════════════════
# XDES-A extends DES with:
#   - 128-bit blocks (dual 64-bit Feistel networks)
#   - Pre/post whitening (DES-X style XOR with derived keys)
#   - Independent round keys from Argon2id KDF

def _xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte sequences (used for pre/post-whitening)."""
    return bytes(x ^ y for x, y in zip(a, b))

def _feistel_half(block_8: bytes, subkeys: list, encrypt: bool) -> bytes:
    """Process one half (8-byte) of XDES-A block using Feistel rounds."""
    keys = subkeys if encrypt else list(reversed(subkeys))  # Reverse keys for decryption
    bits = permute(bytes_to_bits(block_8), IP)  # Initial permutation
    L, R = bits[:32], bits[32:]  # Split into halves
    for K in keys:  # Execute Feistel rounds
        L, R = R, xor_bits(L, feistel(R, K))
    return bits_to_bytes(permute(R + L, IP_INV))  # Final permutation

def xdes_encrypt_block(block_16: bytes, keys: dict) -> bytes:
    """Encrypt a 128-bit block with XDES-A (pre/post whitening + dual Feistel)."""
    L = block_16[:8]   # Left half (8 bytes)
    R = block_16[8:]   # Right half (8 bytes)
    # PRE-WHITENING: XOR with derived pre-key
    L = _xor_bytes(L, keys["pre"])
    R = _xor_bytes(R, keys["pre"])
    rounds = keys["rounds"]  # 16 derived round keys
    # FIRST STAGE: Process each half with first 8 round keys
    L = _feistel_half(L, rounds[:8],  encrypt=True)
    R = _feistel_half(R, rounds[:8],  encrypt=True)
    # MIDDLE CROSS: XOR the halves to increase diffusion
    L, R = _xor_bytes(L, R), _xor_bytes(R, L)
    # SECOND STAGE: Process each half with remaining 8 round keys
    L = _feistel_half(L, rounds[8:], encrypt=True)
    R = _feistel_half(R, rounds[8:], encrypt=True)
    # POST-WHITENING: XOR with derived post-key
    L = _xor_bytes(L, keys["post"])
    R = _xor_bytes(R, keys["post"])
    return L + R  # Return concatenated ciphertext

def xdes_decrypt_block(block_16: bytes, keys: dict) -> bytes:
    """Decrypt a 128-bit block with XDES-A (reverse of encryption)."""
    L = block_16[:8]   # Left half of ciphertext
    R = block_16[8:]   # Right half of ciphertext
    # REMOVE POST-WHITENING: XOR with derived post-key
    L = _xor_bytes(L, keys["post"])
    R = _xor_bytes(R, keys["post"])
    rounds = keys["rounds"]  # 16 derived round keys
    # REVERSE SECOND STAGE: Process with round keys 8-15 in reverse
    L = _feistel_half(L, rounds[8:], encrypt=False)
    R = _feistel_half(R, rounds[8:], encrypt=False)
    # REVERSE MIDDLE CROSS: XOR the halves again (XOR is self-inverse)
    L, R = _xor_bytes(L, R), _xor_bytes(R, L)
    # REVERSE FIRST STAGE: Process with round keys 0-7 in reverse
    L = _feistel_half(L, rounds[:8], encrypt=False)
    R = _feistel_half(R, rounds[:8], encrypt=False)
    # REMOVE PRE-WHITENING: XOR with derived pre-key
    L = _xor_bytes(L, keys["pre"])
    R = _xor_bytes(R, keys["pre"])
    return L + R  # Return concatenated plaintext

# ═════════════════════════════════════════════════════════════════════════════
#  CTR MODE (Counter mode stream cipher for arbitrary-length messages)
# ═════════════════════════════════════════════════════════════════════════════
# CTR mode converts block cipher into stream cipher: each plaintext block XORs
# with an encrypted counter (nonce || counter_value)

def _ctr_keystream_block(nonce: bytes, counter: int, keys: dict) -> bytes:
    """Generate one 128-bit keystream block: encrypt (nonce || counter)."""
    ctr_block = nonce[:8] + struct.pack(">Q", counter)  # 8-byte nonce + 8-byte counter
    return xdes_encrypt_block(ctr_block, keys)  # Encrypt to get keystream

def ctr_encrypt(plaintext: bytes, keys: dict, nonce: bytes) -> bytes:
    """Encrypt plaintext using CTR mode (works for any length, not just multiples of 16)."""
    out = bytearray()
    for i in range(0, len(plaintext), 16):
        chunk = plaintext[i:i+16]  # 16-byte chunk (or less for final block)
        ks = _ctr_keystream_block(nonce, i // 16, keys)  # Generate keystream block
        out += bytes(p ^ k for p, k in zip(chunk, ks[:len(chunk)]))  # XOR with plaintext
    return bytes(out)

# ═════════════════════════════════════════════════════════════════════════════
#  FULL XDES-A PIPELINE (Encrypt-then-MAC with authentication)
# ═════════════════════════════════════════════════════════════════════════════
# Complete encryption: Argon2id KDF → CTR-mode encryption → HMAC-SHA256 tag
# Returns packet: [16-byte salt | 8-byte nonce | ciphertext | 16-byte MAC tag]

def xdes_a_encrypt(plaintext: bytes, password: bytes):
    """Encrypt plaintext with password using XDES-A + Encrypt-then-MAC.
    Returns: (salt, nonce, ciphertext, tag, full_packet, keys)
    """
    """Encrypt plaintext with password using XDES-A + Encrypt-then-MAC.
    Returns: (salt, nonce, ciphertext, tag, full_packet, keys)
    """
    # Generate random salt and nonce
    argon_salt = os.urandom(16)  # 16 random bytes for Argon2id salt
    nonce      = os.urandom(8)   # 8 random bytes for CTR mode nonce
    # Derive keys from password
    keys       = derive_keys(password, argon_salt)
    # Encrypt plaintext in CTR mode
    ciphertext = ctr_encrypt(plaintext, keys, nonce)
    # Compute authentication tag (HMAC-SHA256 over nonce + ciphertext)
    tag        = hmac.new(keys["mac"], nonce + ciphertext, hashlib.sha256).digest()[:16]
    # Assemble packet: salt | nonce | ciphertext | tag
    packet     = argon_salt + nonce + ciphertext + tag
    return argon_salt, nonce, ciphertext, tag, packet, keys

def xdes_a_decrypt(packet: bytes, password: bytes):
    """Decrypt and verify a packet encrypted with xdes_a_encrypt.
    Verifies MAC before decrypting (Encrypt-then-MAC security).
    Returns: (salt, nonce, ciphertext, tag, plaintext, keys)
    """
    # Validate packet length (minimum: 16 salt + 8 nonce + 16 tag)
    if len(packet) < 16 + 8 + 16:
        raise ValueError("Packet too short.")
    # Extract components from packet
    argon_salt = packet[:16]      # First 16 bytes: Argon2id salt
    nonce      = packet[16:24]    # Next 8 bytes: CTR nonce
    tag_recv   = packet[-16:]     # Last 16 bytes: authentication tag
    ciphertext = packet[24:-16]   # Middle bytes: ciphertext
    # Derive keys from password and salt
    keys       = derive_keys(password, argon_salt)
    # Recompute authentication tag
    tag_calc   = hmac.new(keys["mac"], nonce + ciphertext, hashlib.sha256).digest()[:16]
    # Verify tags match (constant-time comparison to prevent timing attacks)
    if not hmac.compare_digest(tag_recv, tag_calc):
        raise ValueError("MAC verification failed — data tampered or wrong key.")
    # MAC verified, safe to decrypt
    plaintext  = ctr_encrypt(ciphertext, keys, nonce)  # CTR mode is symmetric
    return argon_salt, nonce, ciphertext, tag_recv, plaintext, keys

# ═════════════════════════════════════════════════════════════════════════════
#  AVALANCHE ANALYSIS (Test cipher diffusion properties)
# ═════════════════════════════════════════════════════════════════════════════
# Avalanche effect: small change in input should cause large change in output.
# We flip each input bit and measure how many output bits change.

def avalanche_analysis(plaintext: bytes, password: bytes):
    """Analyze avalanche effect: flip each bit and count output bit changes.
    Returns: (avg_changes, percent_avalanche, all_results, detailed_iterations)
    """
    """Analyze avalanche effect: flip each bit and count output bit changes.
    Returns: (avg_changes, percent_avalanche, all_results, detailed_iterations)
    """
    # Prepare test data
    pt      = (plaintext + bytes(16))[:16]  # Ensure 16 bytes
    keys    = derive_keys(password, bytes(16))  # Use fixed salt for reproducibility
    base_ct = xdes_encrypt_block(pt, keys)  # Baseline ciphertext
    results = []
    iterations = []
    # For each of 128 bits in plaintext
    for bit_pos in range(128):
        byte_idx = bit_pos // 8
        bit_idx  = 7 - (bit_pos % 8)
        # Flip one bit
        flipped  = bytearray(pt)
        flipped[byte_idx] ^= (1 << bit_idx)
        # Encrypt flipped plaintext
        fc   = xdes_encrypt_block(bytes(flipped), keys)
        # Count how many output bits changed (Hamming distance)
        diff = sum(bin(x ^ y).count('1') for x, y in zip(base_ct, fc))
        results.append(diff)
        iterations.append({
            "bit": bit_pos,
            "diff": diff,  # Number of output bits that changed
            "ct_hex": fc.hex(),
            "xor_hex": bytes(x ^ y for x, y in zip(base_ct, fc)).hex(),
        })
    # Calculate statistics
    avg = sum(results) / 128  # Average number of output bit changes
    return avg, (avg / 128) * 100, results, iterations  # avg is out of 128 bits


def manual_bit_flipper(plaintext: bytes, password: bytes, flip_positions: list):
    """Flip specified plaintext bit positions and analyze impact on output.
    Args:
        plaintext: Input data (will be padded/truncated to 16 bytes)
        password: Password for key derivation
        flip_positions: List of bit indices (0-127) to flip
    Returns: dict with plaintexts, ciphertexts, XORs, and which bits changed
    """
    # Prepare test data
    pt = (plaintext + bytes(16))[:16]  # Normalize to 16 bytes
    keys = derive_keys(password, bytes(16))  # Derive keys using fixed salt
    base_ct = xdes_encrypt_block(pt, keys)  # Baseline ciphertext

    # Flip specified bits in plaintext
    flipped = bytearray(pt)
    for bit_pos in flip_positions:
        if 0 <= bit_pos < 128:  # Validate bit position
            byte_idx = bit_pos // 8
            bit_idx = 7 - (bit_pos % 8)  # Bit order (MSB first)
            flipped[byte_idx] ^= (1 << bit_idx)  # Toggle bit
    flipped = bytes(flipped)

    # Encrypt the flipped plaintext
    flipped_ct = xdes_encrypt_block(flipped, keys)

    # Compute XOR of plaintexts and ciphertexts (shows which bits differ)
    input_xor = bytes(a ^ b for a, b in zip(pt, flipped))
    output_xor = bytes(a ^ b for a, b in zip(base_ct, flipped_ct))

    # Helper: find all bit positions that are set to 1
    def bits_set(bts):
        """Return list of bit indices (0-127) that are set to 1."""
        out = []
        for i in range(128):
            byte_i = i // 8
            bit_i  = 7 - (i % 8)  # MSB-first bit order
            if (bts[byte_i] >> bit_i) & 1:
                out.append(i)
        return out

    # Find which bits actually changed
    input_changed = bits_set(input_xor)    # Input bits that differ
    output_changed = bits_set(output_xor)  # Output bits that differ

    return {
        "pt_hex": pt.hex(),
        "flipped_pt_hex": flipped.hex(),
        "base_ct_hex": base_ct.hex(),
        "flipped_ct_hex": flipped_ct.hex(),
        "input_xor_hex": input_xor.hex(),
        "output_xor_hex": output_xor.hex(),
        "input_changed": input_changed,       # List of changed input bit positions
        "output_changed": output_changed,     # List of changed output bit positions
        "input_changed_count": len(input_changed),   # How many input bits differ
        "output_changed_count": len(output_changed), # How many output bits differ
    }

# ═════════════════════════════════════════════════════════════════════════════
#  BRUTE FORCE ANALYSIS (Password security estimation + cracking tools)
# ═════════════════════════════════════════════════════════════════════════════
# Tools to test password strength and estimate time to crack with CPU/ASIC attacks

WEAK_PASSWORDS = [  # Common weak passwords for testing
    "password", "123456", "qwerty", "abc123", "letmein",
    "monkey", "dragon", "master", "sunshine", "princess",
    "admin", "login", "welcome", "shadow", "superman",
    "iloveyou", "trustno1", "hello", "password1", "test",
]

def estimate_crack_time(password: str) -> dict:
    """Estimate how long it would take to crack password via brute force.
    Assumes optimized SHA256 and constant-time Argon2id rates.
    """
    """Estimate how long it would take to crack password via brute force.
    Assumes optimized SHA256 and constant-time Argon2id rates.
    """
    # Determine character set used in password
    charset = 0
    if any(c.islower() for c in password): charset += 26  # Lowercase letters
    if any(c.isupper() for c in password): charset += 26  # Uppercase letters
    if any(c.isdigit() for c in password): charset += 10  # Digits
    if any(not c.isalnum() for c in password): charset += 32  # Special characters
    charset = max(charset, 1)

    # Calculate keyspace (total possible passwords of same length and charset)
    keyspace    = charset ** len(password)
    # Performance estimates (attacks per second on specialized hardware)
    SHA256_RATE = 10_000_000_000  # ~10 billion SHA256/sec (GPU/ASIC)
    ARGON2_RATE = 10              # ~10 Argon2id/sec (memory-hard, slow)

    # Calculate average time to crack (keyspace / 2 because average = half keyspace)
    sha_secs = keyspace / 2 / SHA256_RATE
    arg_secs = keyspace / 2 / ARGON2_RATE

    # Helper: format seconds as human-readable time and return security rating
    def fmt(secs):
        """Convert seconds to human-readable time and return security rating."""
        if secs < 1:        return "< 1 second",      "CRITICAL"
        if secs < 60:       return f"{secs:.1f}s",     "CRITICAL"
        if secs < 3600:     return f"{secs/60:.1f} min","WEAK"
        if secs < 86400:    return f"{secs/3600:.1f} hr","WEAK"
        if secs < 2592000:  return f"{secs/86400:.1f} days","MODERATE"
        if secs < 31536000: return f"{secs/2592000:.1f} mo","STRONG"
        y = secs / 31536000
        if y < 1e6:  return f"{y:,.0f} yrs",  "STRONG"
        if y < 1e12: return f"{y:.2e} yrs",   "VERY STRONG"
        return f"{y:.2e} yrs", "UNBREAKABLE"

    # Format both SHA256 and Argon2id times
    sha_str, sha_rating = fmt(sha_secs)
    arg_str, arg_rating = fmt(arg_secs)

    return {
        "length":          len(password),           # Password length
        "charset":         charset,                 # Character set size
        "keyspace":        keyspace,                # Total possible passwords
        "sha256_secs":     sha_secs,                # Time with fast SHA256
        "sha256_str":      sha_str,                 # Formatted time string
        "sha256_rating":   sha_rating,              # Security rating for SHA256
        "argon2_secs":     arg_secs,                # Time with slow Argon2id
        "argon2_str":      arg_str,                 # Formatted time string
        "argon2_rating":   arg_rating,              # Security rating for Argon2id
        "slowdown_factor": arg_secs / max(sha_secs, 1e-9),  # Argon2id slowdown vs SHA256
    }

# ═════════════════════════════════════════════════════════════════════════════
#  LIVE BRUTE FORCE ENGINE (Multiprocessing-based password cracking)
# ═════════════════════════════════════════════════════════════════════════════
# Distributed brute force attack using multiprocessing for CPU parallelism.
# Tests each candidate password and returns immediately on first match.

import multiprocessing as mp

# Character sets for different password space assumptions
BRUTE_CHARSET_ALPHA    = "abcdefghijklmnopqrstuvwxyz"  # Lowercase only
BRUTE_CHARSET_ALPHANUM = "abcdefghijklmnopqrstuvwxyz0123456789"  # Letters + digits
BRUTE_CHARSET_COMMON   = "abcdefghijklmnopqrstuvwxyz0123456789!@#"  # Common subset
BRUTE_CHARSET_FULL     = (  # Full ASCII printable
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789!@#$%^&*()-_=+[]{}|;:',.<>?/`~"
)

def _candidate_to_des_key(candidate: str) -> bytes:
    """Convert a string candidate to an 8-byte DES key (pad/truncate as needed)."""
    raw = candidate.encode("utf-8")
    return (raw * ((8 // len(raw)) + 1))[:8]  # Repeat to 8 bytes, then truncate


# ── DES worker (runs in subprocess) ──────────────────────────────────────────

def _des_worker_batch(args):
    """Worker function: test a batch of DES key candidates in a subprocess.
    Returns the matching candidate (if found) or None.
    """
    candidates, known_pt8, target_ct = args
    # Try each candidate until we find a match
    for candidate in candidates:
        key8 = _candidate_to_des_key(candidate)  # Convert candidate to 8-byte key
        ct   = des_encrypt_block(known_pt8, key8)  # Encrypt with this key
        if ct == target_ct:  # Match found!
            return candidate
    return None  # No match in this batch


# ── XDES worker (runs in subprocess) ─────────────────────────────────────────

def _xdes_worker_batch(args):
    """Worker function: test a batch of XDES-A key candidates in a subprocess.
    Returns the matching candidate (if found) or None.
    """
    candidates, known_pt16, argon_salt, target_ct = args
    # Try each candidate until we find a match
    for candidate in candidates:
        keys = derive_keys(candidate.encode("utf-8"), argon_salt)  # Derive keys with KDF
        ct   = xdes_encrypt_block(known_pt16, keys)  # Encrypt with derived keys
        if ct == target_ct:  # Match found!
            return candidate
    return None  # No match in this batch


# ── Batch generator ───────────────────────────────────────────────────────────

def _generate_batches(charset, max_len, batch_size):
    """Generate candidate password batches up to max_len using charset.
    Yields (batch_index, [candidate, ...]) tuples of batch_size.
    """
    batch = []
    idx   = 0
    # Generate all combinations: length 1, 2, 3, ... up to max_len
    for length in range(1, max_len + 1):
        # Generate all strings of this length from charset
        for combo in itertools.product(charset, repeat=length):
            batch.append("".join(combo))
            # Yield batch when it reaches batch_size
            if len(batch) >= batch_size:
                yield idx, batch
                idx  += len(batch)
                batch = []
    # Yield remaining partial batch
    if batch:
        yield idx, batch


# ── DES brute force ───────────────────────────────────────────────────────────

def brute_force_des(
    target_ct: bytes,
    known_pt:  bytes,
    max_len:   int,
    charset:   str,
    stop_event,
    on_attempt,
    on_done,
):
    """Brute force DES: try all passwords up to max_len from charset.
    Args:
        target_ct: Ciphertext to match (8 bytes)
        known_pt: Known plaintext (will use first 8 bytes)
        max_len: Maximum password length to try
        charset: Character set to use for candidate generation
        stop_event: multiprocessing.Event to signal early termination
        on_attempt: Callback(attempt_count, last_candidate, elapsed, success)
        on_done: Callback(success, password, attempt_count, elapsed)
    """
    # Prepare plaintext
    pt8        = known_pt[:8].ljust(8, b'\x00')  # Ensure 8 bytes
    # Setup multiprocessing
    n_workers  = max(1, mp.cpu_count())  # One worker per CPU core
    batch_size = max(500, n_workers * 200)  # Candidates per batch
    attempt    = 0
    start      = time.perf_counter()

    # Main brute force loop
    with mp.Pool(n_workers) as pool:
        # Generate candidate batches
        for base_idx, batch in _generate_batches(charset, max_len, batch_size):
            # Check for early termination signal
            if stop_event.is_set():
                pool.terminate()
                on_done(False, "", attempt, time.perf_counter() - start)
                return

            # Divide batch into chunks for parallel processing
            chunk_size = max(1, len(batch) // n_workers)
            chunks     = [batch[i:i+chunk_size]
                          for i in range(0, len(batch), chunk_size)]
            work       = [(c, pt8, target_ct) for c in chunks]  # Work items for workers

            # Process chunks in parallel
            for result in pool.imap_unordered(_des_worker_batch, work):
                attempt += len(batch) // len(chunks)  # Increment attempt counter
                elapsed  = time.perf_counter() - start
                if result is not None:  # Password found!
                    on_attempt(attempt, result, elapsed, True)
                    pool.terminate()
                    on_done(True, result, attempt, elapsed)
                    return
                on_attempt(attempt, batch[min(attempt-1, len(batch)-1)], elapsed, False)

    # No password found
    on_done(False, "", attempt, time.perf_counter() - start)


# ── XDES brute force ──────────────────────────────────────────────────────────

def brute_force_xdes(
    target_ct:  bytes,
    known_pt:   bytes,
    argon_salt: bytes,
    max_len:    int,
    charset:    str,
    stop_event,
    on_attempt,
    on_done,
):
    """Brute force XDES-A: try all passwords up to max_len from charset.
    Args:
        target_ct: Ciphertext to match (16 bytes)
        known_pt: Known plaintext (will use first 16 bytes)
        argon_salt: Argon2id salt from the packet (16 bytes)
        max_len: Maximum password length to try
        charset: Character set to use for candidate generation
        stop_event: multiprocessing.Event to signal early termination
        on_attempt: Callback(attempt_count, last_candidate, elapsed, success)
        on_done: Callback(success, password, attempt_count, elapsed)
    """
    # Prepare plaintext
    pt16       = (known_pt + bytes(16))[:16]  # Ensure 16 bytes
    # Setup multiprocessing
    n_workers  = max(1, mp.cpu_count())  # One worker per CPU core
    batch_size = max(n_workers, n_workers * 2)  # Candidates per batch
    attempt    = 0
    start      = time.perf_counter()

    # Main brute force loop
    with mp.Pool(n_workers) as pool:
        # Generate candidate batches
        for base_idx, batch in _generate_batches(charset, max_len, batch_size):
            # Check for early termination signal
            if stop_event.is_set():
                pool.terminate()
                on_done(False, "", attempt, time.perf_counter() - start)
                return

            # Divide batch into chunks for parallel processing
            chunk_size = max(1, len(batch) // n_workers)
            chunks     = [batch[i:i+chunk_size]
                          for i in range(0, len(batch), chunk_size)]
            work       = [(c, pt16, argon_salt, target_ct) for c in chunks]  # Work items

            # Process chunks in parallel
            for result in pool.imap_unordered(_xdes_worker_batch, work):
                attempt += max(1, len(batch) // len(chunks))  # Increment attempt counter
                elapsed  = time.perf_counter() - start
                if result is not None:  # Password found!
                    on_attempt(attempt, result, elapsed, True)
                    pool.terminate()
                    on_done(True, result, attempt, elapsed)
                    return
                on_attempt(attempt, batch[min(attempt-1, len(batch)-1)], elapsed, False)

    # No password found
    on_done(False, "", attempt, time.perf_counter() - start)