#!/usr/bin/env python3
"""
self_encrypt_viz.py

Human-observable visualization of a self-encrypting text.

Usage examples:
  python self_encrypt_viz.py encrypt "Secret message" mypassword --delay 0.06
  python self_encrypt_viz.py decrypt <token> mypassword
  python self_encrypt_viz.py encrypt "Secret message" mypassword --gui --delay 0.03

Notes:
 - Requires `cryptography`. Optional: `tqdm` and `matplotlib` for nicer visuals.
 - The "visualization" deliberately slows and reveals intermediate states
   but does NOT change the cryptography: all cryptographic work is performed
   using secure primitives (PBKDF2-HMAC-SHA256 + AES-GCM).
"""
import argparse
import base64
import os
import sys
import threading
import time
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Optional niceties
try:
    from tqdm import tqdm
except Exception:
    tqdm = None

try:
    import matplotlib.pyplot as plt
    import numpy as np
    MATPLOTLIB_AVAILABLE = True
except Exception:
    MATPLOTLIB_AVAILABLE = False

# --- Crypto parameters (safe defaults) ---
SALT_SIZE = 16
NONCE_SIZE = 12
KDF_ITERATIONS = 200_000
KEY_LEN = 32

# --- Utilities ---
def derive_key(password: str, salt: bytes, iterations: int = KDF_ITERATIONS) -> bytes:
    """Derive a symmetric key from a password using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))

# --- Visualization helpers ---
def nice_hex_chunks(b: bytes, chunk_size: int = 16):
    """Yield hex strings of bytes in chunks."""
    for i in range(0, len(b), chunk_size):
        yield b[i:i+chunk_size].hex()

def terminal_sleep(delay: float):
    """Sleep but allow for KeyboardInterrupt responsiveness."""
    try:
        time.sleep(delay)
    except KeyboardInterrupt:
        raise

def show_matplotlib_reveal(plaintext: bytes, ciphertext: bytes, delay: float):
    """
    Optional Matplotlib visualization:
    - Displays two grayscale rows: plaintext bytes (top), ciphertext bytes (bottom).
    - Reveals ciphertext bytes gradually.
    """
    if not MATPLOTLIB_AVAILABLE:
        print("[matplotlib not available — skipping GUI visualization]")
        return

    # Normalize to 0..1 for grayscale, shape to 2 x N array
    n = max(len(plaintext), len(ciphertext))
    def to_row(b):
        arr = np.zeros(n, dtype=np.uint8)
        arr[:len(b)] = np.frombuffer(b, dtype=np.uint8)
        return arr

    pt_row = to_row(plaintext)
    ct_row = to_row(ciphertext)
    grid = np.vstack([pt_row, np.zeros_like(ct_row)])  # start with zeros on second row

    fig, ax = plt.subplots(figsize=(max(5, n/20), 2))
    im = ax.imshow(grid, cmap='gray', aspect='auto', vmin=0, vmax=255)
    ax.set_yticks([0,1])
    ax.set_yticklabels(['plaintext','ciphertext'])
    ax.set_xticks([])

    plt.ion()
    plt.show()

    # Reveal ciphertext bytes slowly
    for i in range(len(ciphertext)):
        grid[1, i] = ct_row[i]
        im.set_data(grid)
        fig.canvas.draw_idle()
        plt.pause(delay)
    # keep window open
    print("[GUI visualization complete — close the window to continue]")
    plt.ioff()
    plt.show(block=True)

# --- High-level encrypt/decrypt with visualization ---
def encrypt_visual(plaintext: str, password: str, delay: float = 0.05, gui: bool = False) -> str:
    """
    Encrypt plaintext with a password while visualizing:
      1) Salt generation
      2) KDF progress (simulated progress with real KDF running in a thread)
      3) Nonce generation
      4) Encryption progress (simulated)
      5) Reveal ciphertext in chunks
      6) Pack and base64-encode result
    Returns base64 token.
    """
    print("=== Encrypt: human-friendly visualization ===")
    print("Step 1: Generating salt (random bytes)...")
    salt = os.urandom(SALT_SIZE)
    print(f"  salt ({len(salt)} bytes): {salt.hex()}\n")
    terminal_sleep(delay * 6)

    # Step 2: Derive key with KDF in a thread, show progress bar in main thread
    print("Step 2: Deriving key with PBKDF2-HMAC-SHA256")
    kdf_result = {"key": None, "error": None, "done": False}

    def kdf_thread():
        try:
            key = derive_key(password, salt, iterations=KDF_ITERATIONS)
            kdf_result["key"] = key
        except Exception as e:
            kdf_result["error"] = e
        finally:
            kdf_result["done"] = True

    thread = threading.Thread(target=kdf_thread, daemon=True)
    thread.start()

    # Simulated progress length (bounded): we don't want like 200k ticks — scale to e.g. 100 steps
    progress_steps = 100
    for i in (range(progress_steps) if tqdm is None else tqdm(range(progress_steps), desc="KDF")):
        if kdf_result["done"]:
            # finish immediately if KDF finished early
            break
        terminal_sleep(delay * 0.5)
    # Wait for thread to finish if not yet
    while not kdf_result["done"]:
        terminal_sleep(delay * 0.1)
    if kdf_result["error"]:
        raise kdf_result["error"]
    key = kdf_result["key"]
    print("  Key derived (length %d bytes).\n" % len(key))
    terminal_sleep(delay * 6)

    # Step 3: Nonce generation
    print("Step 3: Generating nonce (IV)...")
    nonce = os.urandom(NONCE_SIZE)
    print(f"  nonce ({len(nonce)} bytes): {nonce.hex()}\n")
    terminal_sleep(delay * 4)

    # Step 4: Encrypt (we will simulate a slow process)
    print("Step 4: Encrypting plaintext with AES-GCM (visualizing)....")
    aesgcm = AESGCM(key)
    # Perform actual encryption in thread to avoid long blocking UI
    enc_result = {"ct": None, "error": None, "done": False}

    def enc_thread():
        try:
            ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), associated_data=None)
            enc_result["ct"] = ct
        except Exception as e:
            enc_result["error"] = e
        finally:
            enc_result["done"] = True

    t2 = threading.Thread(target=enc_thread, daemon=True)
    t2.start()

    # Visual spinner while encrypting
    spinner = "|/-\\"
    spin_i = 0
    while not enc_result["done"]:
        sys.stdout.write(f"\r  Encrypting... {spinner[spin_i % len(spinner)]}")
        sys.stdout.flush()
        spin_i += 1
        terminal_sleep(delay * 0.3)
    sys.stdout.write("\r  Encrypting... done!        \n")
    if enc_result["error"]:
        raise enc_result["error"]
    ct = enc_result["ct"]

    terminal_sleep(delay * 4)

    # Step 5: Reveal ciphertext bytes slowly in hex chunks
    print("Step 5: Revealing ciphertext (tag included).")
    # chunk size is chosen for readable reveal
    chunk_size = 16
    ct_len = len(ct)
    print(f"  ciphertext total bytes: {ct_len}")
    revealed = bytearray()
    for i in range(0, ct_len, chunk_size):
        chunk = ct[i:i+chunk_size]
        revealed.extend(chunk)
        hex_chunk = chunk.hex()
        print(f"   + bytes {i:4d}-{min(i+chunk_size, ct_len)-1:4d}: {hex_chunk}")
        terminal_sleep(delay * 12)  # slow reveal; control with --delay
    print("  Full ciphertext revealed.\n")

    # Optional GUI visual: show plaintext vs ciphertext
    if gui:
        try:
            print("Step 6: GUI visualization (plaintext → ciphertext).")
            show_matplotlib_reveal(plaintext.encode("utf-8"), ct, delay)
        except KeyboardInterrupt:
            print("[GUI interrupted by user]")

    # Pack salt || nonce || ct
    blob = salt + nonce + ct
    token_b64 = base64.urlsafe_b64encode(blob).decode("ascii")
    print("Step 7: Packing (salt || nonce || ciphertext) into base64 token.")
    print("  Token length:", len(token_b64))
    print("\nEncryption complete. Copy the token to decrypt later.\n")
    return token_b64

def decrypt_visual(token_b64: str, password: str, delay: float = 0.05, gui: bool = False) -> str:
    """
    Visual decrypt: show unpacking, KDF progress, and decryption attempt.
    """
    print("=== Decrypt: human-friendly visualization ===")
    try:
        blob = base64.urlsafe_b64decode(token_b64.encode("ascii"))
    except Exception:
        raise ValueError("Invalid base64 token")

    if len(blob) < SALT_SIZE + NONCE_SIZE + 16:
        raise ValueError("Token too short / corrupted")

    salt = blob[:SALT_SIZE]
    nonce = blob[SALT_SIZE:SALT_SIZE+NONCE_SIZE]
    ct = blob[SALT_SIZE+NONCE_SIZE:]
    print(f"Step 1: Unpacked token -> salt({len(salt)} bytes), nonce({len(nonce)} bytes), ciphertext({len(ct)} bytes).")
    print(f"  salt: {salt.hex()}")
    print(f"  nonce: {nonce.hex()}\n")
    terminal_sleep(delay * 6)

    # KDF progress similar to encrypt
    print("Step 2: Deriving key with PBKDF2-HMAC-SHA256 (visualized)")
    kdf_result = {"key": None, "error": None, "done": False}

    def kdf_thread():
        try:
            key = derive_key(password, salt, iterations=KDF_ITERATIONS)
            kdf_result["key"] = key
        except Exception as e:
            kdf_result["error"] = e
        finally:
            kdf_result["done"] = True

    thread = threading.Thread(target=kdf_thread, daemon=True)
    thread.start()

    progress_steps = 100
    for i in (range(progress_steps) if tqdm is None else tqdm(range(progress_steps), desc="KDF")):
        if kdf_result["done"]:
            break
        terminal_sleep(delay * 0.5)
    while not kdf_result["done"]:
        terminal_sleep(delay * 0.1)
    if kdf_result["error"]:
        raise kdf_result["error"]
    key = kdf_result["key"]
    print("  Key derived.\n")
    terminal_sleep(delay * 4)

    # Show ciphertext chunks as they're "fed" to decrypt
    print("Step 3: Feeding ciphertext to AES-GCM (revealing chunks)...")
    for i, chunk in enumerate(nice_hex_chunks(ct, 16)):
        print(f"   chunk {i:03d}: {chunk}")
        terminal_sleep(delay * 8)

    # Attempt decryption
    print("\nStep 4: Attempting decryption...")
    aesgcm = AESGCM(key)
    try:
        plaintext_bytes = aesgcm.decrypt(nonce, ct, associated_data=None)
    except Exception as e:
        raise ValueError("Decryption failed (wrong password or corrupted token)") from e

    plaintext = plaintext_bytes.decode("utf-8")
    print("  Decryption successful. Plaintext recovered.\n")

    if gui:
        try:
            print("Step 5: GUI visualization (ciphertext → plaintext).")
            # For GUI, show plaintext under ciphertext (we reveal plaintext)
            show_matplotlib_reveal(plaintext.encode("utf-8"), ct, delay)
        except KeyboardInterrupt:
            print("[GUI interrupted by user]")

    return plaintext

# --- CLI ---
def main(args_list=None):
    parser = argparse.ArgumentParser(description="Self-encrypting text with visualization for humans.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_enc = sub.add_parser("encrypt", help="Encrypt text with visualization")
    p_enc.add_argument("plaintext", type=str, help="Plaintext to encrypt (wrap in quotes if spaces).")
    p_enc.add_argument("password", type=str, help="Password / passphrase.")
    p_enc.add_argument("--delay", type=float, default=0.05, help="Base delay multiplier for visualization (seconds). Smaller = faster.")
    p_enc.add_argument("--gui", action="store_true", help="Open a matplotlib GUI visualization (optional).")

    p_dec = sub.add_parser("decrypt", help="Decrypt token with visualization")
    p_dec.add_argument("token", type=str, help="Base64 token returned by encrypt.")
    p_dec.add_argument("password", type=str, help="Password / passphrase.")
    p_dec.add_argument("--delay", type=float, default=0.05, help="Base delay multiplier for visualization (seconds).")
    p_dec.add_argument("--gui", action="store_true", help="Open a matplotlib GUI visualization (optional).")

    args = parser.parse_args(args=args_list)

    if args.cmd == "encrypt":
        token = encrypt_visual(args.plaintext, args.password, delay=args.delay, gui=args.gui)
        print("\n=== OUTPUT TOKEN ===")
        print(token)
    elif args.cmd == "decrypt":
        plaintext = decrypt_visual(args.token, args.password, delay=args.delay, gui=args.gui)
        print("\n=== RECOVERED PLAINTEXT ===")
        print(plaintext)

if __name__ == "__main__":
    # No automatic call to main() here. User will call main() with arguments or the specific functions.
    # try:
    #     main([]) # Pass an empty list to avoid parsing kernel arguments by default
    # except KeyboardInterrupt:
    #     print("\n[Interrupted by user]")
    #     sys.exit(130)
    # except Exception as e:
    #     print("ERROR:", e, file=sys.stderr)
    #     sys.exit(2)
    pass
