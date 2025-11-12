#!/usr/bin/env python3
"""
crypt_poem_3.py — now supports file encryption/decryption
---------------------------------------------------------
Encrypt text or .txt files with human-visible visualization.
NOTE: This version uses an INSECURE XOR cipher for visual demonstration purposes.

Examples:
  # Encrypt plaintext
  python crypt_poem_3.py encrypt "Roses are red, Violets are blue." mypassword

  # Encrypt file
  python crypt_poem_3.py encrypt-file poem.txt mypassword --delay 0.001 but can be set to .05

  # Decrypt file
  python crypt_poem_3.py decrypt-file poem.txt.enc mypassword
"""

import argparse, base64, os, sys, threading, time
from typing import Optional

# Removed cryptography imports:
# from cryptography.hazmat.primitives.ciphers.aead import AESGCM
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# optional extras
try:
    from tqdm import tqdm
except Exception:
    tqdm = None
try:
    import matplotlib.pyplot as plt, numpy as np
    MATPLOTLIB_AVAILABLE = True
except Exception:
    MATPLOTLIB_AVAILABLE = False

# --- constants ---
# These are no longer necessary for XOR, but kept for function compatibility
SALT_SIZE = 0
NONCE_SIZE = 0
KDF_ITERATIONS = 0
KEY_LEN = 0

# --- helpers ---
# Modified to generate a repeating key for XOR
def derive_key(password: str, salt: bytes = b'', iterations: int = 0) -> bytes:
    """Uses the password directly as the key."""
    # We ignore salt/iterations for simple XOR. The password itself is the repeating key.
    return password.encode("utf-8")

# XOR encryption/decryption function
def xor_crypt(data: bytes, key: bytes) -> bytes:
    """Performs XOR operation using a repeating key."""
    output = bytearray()
    key_len = len(key)
    for i, byte in enumerate(data):
        output.append(byte ^ key[i % key_len])
    return bytes(output)

def terminal_sleep(delay: float):
    try:
        # Flush required for fast terminal updates
        sys.stdout.flush() 
        time.sleep(delay)
    except KeyboardInterrupt:
        raise

# Matplotlib visualization is now adjusted for same-length plaintext/ciphertext
def show_matplotlib_reveal(plaintext: bytes, ciphertext: bytes, delay: float):
    if not MATPLOTLIB_AVAILABLE:
        print("[matplotlib not available — skipping GUI visualization]")
        return
    n = max(len(plaintext), len(ciphertext))
    def row(b):
        arr = np.zeros(n, dtype=np.uint8)
        arr[:len(b)] = np.frombuffer(b, dtype=np.uint8)
        return arr
    pt, ct = row(plaintext), row(ciphertext)
    grid = np.vstack([pt, np.zeros_like(ct)])
    fig, ax = plt.subplots(figsize=(max(5, n/20), 2))
    im = ax.imshow(grid, cmap="gray", aspect="auto", vmin=0, vmax=255)
    ax.set_yticks([0,1]); ax.set_yticklabels(["plaintext","ciphertext"]); ax.set_xticks([])
    plt.ion(); plt.show()
    for i in range(len(ciphertext)):
        grid[1,i] = ct[i]
        im.set_data(grid)
        fig.canvas.draw_idle()
        plt.pause(delay)
    print("[Close GUI window to continue]")
    plt.ioff(); plt.show(block=True)


# --- encryption / decryption core ---
def encrypt_visual(plaintext: str, password: str, delay=0, gui=False) -> str:
    print("=== Encrypting (visual mode - INSECURE XOR) ===")
    
    # Derivation is now instant
    key = derive_key(password)
    print(f"Key derived: '{key.decode()}' (Length: {len(key)})")
    terminal_sleep(delay*4)

    plaintext_bytes = plaintext.encode("utf-8")
    ct = xor_crypt(plaintext_bytes, key)
    
    # --- MODIFIED: Direct Replacement Logic ---
    print(f"\nPlaintext ({len(plaintext_bytes)} bytes):")
    
    # Print original plaintext
    sys.stdout.write(f"  {plaintext}\r") 
    terminal_sleep(delay * 10)
    
    print("\nVisualizing Encryption (character-by-character replacement):")
    
    # Use the ciphertext bytes directly
    current_output = bytearray(plaintext_bytes)
    
    # Loop over the bytes and replace one by one
    for i in range(len(ct)):
        current_output[i] = ct[i]
        
        # Print the partially encrypted output, then carriage return
        # We use 'latin-1' encoding as it maps byte values 0-255 to the first 256 Unicode characters
        # which is useful for displaying non-printable bytes resulting from XOR.
        line_out = current_output.decode('latin-1')
        sys.stdout.write(f"  {line_out}\r") 
        terminal_sleep(delay * 2) 

    # Final result without carriage return
    final_ciphertext_str = current_output.decode('latin-1')
    print(f"  {final_ciphertext_str}") 
    
    print(f"\nFinal Ciphertext ({len(ct)} bytes):")
    print(f"  {final_ciphertext_str}")
    # --- END MODIFIED SECTION ---

    if gui: show_matplotlib_reveal(plaintext_bytes, ct, delay)
    
    # For storage, we encode the result to Base64 (Token is just the ciphertext now)
    token = base64.urlsafe_b64encode(ct).decode()
    print("\n✅ Encryption complete.")
    return token

def decrypt_visual(token: str, password: str, delay=0, gui=False) -> str:
    print("=== Decrypting (visual mode - INSECURE XOR) ===")
    
    ct = base64.urlsafe_b64decode(token)
    
    key = derive_key(password)
    print(f"Key derived: '{key.decode()}'")
    terminal_sleep(delay*4)
    
    # Perform decryption (XOR is symmetric)
    try: 
        pt_bytes = xor_crypt(ct, key)
        pt = pt_bytes.decode('utf-8')
    except Exception: 
        sys.exit("❌ Wrong password or corrupted file.")
    
    print("Feeding ciphertext...")
    
    # --- MODIFIED: Decryption Replacement Logic ---
    # Decrypting visualization: replace ciphertext with plaintext
    print(f"\nCiphertext ({len(ct)} bytes):")
    
    # Print original ciphertext
    sys.stdout.write(f"  {ct.decode('latin-1')}\r") 
    terminal_sleep(delay * 10)
    
    print("\nVisualizing Decryption (character-by-character replacement):")
    
    current_output = bytearray(ct)
    
    # Loop over the bytes and replace one by one
    for i in range(len(pt_bytes)):
        current_output[i] = pt_bytes[i]
        
        # Print the partially decrypted output, then carriage return
        line_out = current_output.decode('latin-1')
        sys.stdout.write(f"  {line_out}\r") 
        terminal_sleep(delay * 2) 

    # Final result without carriage return
    final_plaintext_str = current_output.decode('utf-8')
    print(f"  {final_plaintext_str}") 
    
    print("✅ Decryption successful.\n")
    if gui: show_matplotlib_reveal(pt_bytes, ct, delay)
    return final_plaintext_str

# --- new file-based functions (Unchanged) ---
def encrypt_file_visual(filepath: str, password: str, delay=0, gui=False):
    if not os.path.exists(filepath):
        sys.exit("File not found.")
    with open(filepath,"r",encoding="utf-8") as f: text=f.read()
    token = encrypt_visual(text, password, delay, gui)
    outpath = filepath + ".enc"
    with open(outpath,"w",encoding="utf-8") as f: f.write(token)
    print(f"✅ Encrypted file written to {outpath}")

def decrypt_file_visual(filepath: str, password: str, delay=0, gui=False):
    if not os.path.exists(filepath):
        sys.exit("Encrypted file not found.")
    with open(filepath,"r",encoding="utf-8") as f: token=f.read().strip()
    plaintext = decrypt_visual(token, password, delay, gui)
    outpath = filepath.replace(".enc",".decrypted.txt")
    with open(outpath,"w",encoding="utf-8") as f: f.write(plaintext)
    print(f"✅ Decrypted text written to {outpath}")

# --- CLI interface (Unchanged) ---
def main():
    p = argparse.ArgumentParser(description="Encrypt or decrypt text or files with visualization.")
    sub = p.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("encrypt", help="Encrypt plaintext")
    p1.add_argument("plaintext"); p1.add_argument("password")
    p1.add_argument("--delay",type=float,default=0.001); p1.add_argument("--gui",action="store_true")

    p2 = sub.add_parser("decrypt", help="Decrypt base64 token")
    p2.add_argument("token"); p2.add_argument("password")
    p2.add_argument("--delay",type=float,default=0.001); p2.add_argument("--gui",action="store_true")

    pf1 = sub.add_parser("encrypt-file", help="Encrypt a .txt file")
    pf1.add_argument("file"); pf1.add_argument("password")
    pf1.add_argument("--delay",type=float,default=0.001); pf1.add_argument("--gui",action="store_true")

    pf2 = sub.add_parser("decrypt-file", help="Decrypt a .enc file")
    pf2.add_argument("file"); pf2.add_argument("password")
    pf2.add_argument("--delay",type=float,default=0.001); pf2.add_argument("--gui",action="store_true")

    a = p.parse_args()
    if a.cmd=="encrypt": print(encrypt_visual(a.plaintext,a.password,a.delay,a.gui))
    elif a.cmd=="decrypt": print(decrypt_visual(a.token,a.password,a.delay,a.gui))
    elif a.cmd=="encrypt-file": encrypt_file_visual(a.file,a.password,a.delay,a.gui)
    elif a.cmd=="decrypt-file": decrypt_file_visual(a.file,a.password,a.delay,a.gui)

if __name__=="__main__":
    try: main()
    except KeyboardInterrupt:
        print("\n[Interrupted]")
        sys.exit(130)