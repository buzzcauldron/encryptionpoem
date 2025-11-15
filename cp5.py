#!/usr/bin/env python3
"""
crypt_poem_3.py — now supports file encryption/decryption
---------------------------------------------------------
Encrypt text or .txt files with human-visible visualization.

Examples:
  # Encrypt plaintext
  python crypt_poem_3.py encrypt "Roses are red" mypassword

  # Encrypt file
  python crypt_poem_3.py encrypt-file poem.txt mypassword --delay 0.05

  # Decrypt file
  python crypt_poem_3.py decrypt-file poem.txt.enc mypassword
"""

import argparse, base64, os, sys, threading, time
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

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
SALT_SIZE = 16
NONCE_SIZE = 12
KDF_ITERATIONS = 200_000
KEY_LEN = 32

# --- helpers ---
def derive_key(password: str, salt: bytes, iterations: int = KDF_ITERATIONS) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))

def nice_hex_chunks(b: bytes, chunk_size: int = 16):
    for i in range(0, len(b), chunk_size):
        yield b[i:i+chunk_size].hex()

def terminal_sleep(delay: float):
    # Added a try/except around time.sleep to ensure smooth console updates
    # This is critical for the printing loop to work on some systems.
    try:
        time.sleep(delay)
    except KeyboardInterrupt:
        raise

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
def encrypt_visual(plaintext: str, password: str, delay=0.05, gui=False) -> str:
    print("=== encrypting ===")
    salt = os.urandom(SALT_SIZE)
    print(f"salt in the wound({SALT_SIZE} bytes): {salt.hex()}")
    terminal_sleep(delay*6)

    print("deriving key...")
    kdf_res = {"key":None,"done":False,"err":None}
    def kdf_t():
        try: kdf_res["key"]=derive_key(password,salt)
        except Exception as e: kdf_res["err"]=e
        finally: kdf_res["done"]=True
    t = threading.Thread(target=kdf_t,daemon=True); t.start()
    for _ in (range(100) if tqdm is None else tqdm(range(100),desc="KDF")):
        if kdf_res["done"]: break
        terminal_sleep(delay*0.5)
    while not kdf_res["done"]: terminal_sleep(delay*0.1)
    if kdf_res["err"]: raise kdf_res["err"]
    key = kdf_res["key"]; print("key derived\n")

    nonce = os.urandom(NONCE_SIZE)
    print(f"nonce ({NONCE_SIZE} bytes): {nonce.hex()}")
    terminal_sleep(delay*4)

    aes = AESGCM(key)
    print("encoding...")
    
    # Perform encryption
    plaintext_bytes = plaintext.encode()
    ct = aes.encrypt(nonce, plaintext_bytes, None)
    
    # --- MODIFIED: PRINT AND REPLACE LOGIC ---
    print(f"\n you wrote:({len(plaintext_bytes)} bytes):")
    
    # Initial print of plaintext (using a placeholder for alignment)
    print_length = len(plaintext_bytes) * 2 # To align with hex length later
    
    # Pad the plaintext if needed to match the *potential* length of the ciphertext for smooth replacement, 
    # but for AES-GCM, the ciphertext is usually only slightly longer (16 bytes for auth tag), 
    # so we'll base the display length on the ciphertext length for a full visual change.
    
    # Use the ciphertext length for the total visual length
    display_length = len(ct) * 2 # Hex is 2 chars per byte
    
    # Plaintext line is just the text, but the replacement line is HEX.
    # To demonstrate replacement, let's print the plaintext and then overwrite it.
    
    # Print plaintext
    print(f"  {plaintext}") 
    terminal_sleep(delay * 10)
    
    # Calculate the total length of the final hex output line, including separators.
    HEX_CHUNK_SIZE = 16
    total_hex_len = 0
    
    # Generate chunks and calculate total line length (16 bytes = 32 chars + 1 space)
    ct_chunks = list(nice_hex_chunks(ct, HEX_CHUNK_SIZE))
    
    # Build a string of placeholder characters ('..') that is the full length of the final hex output
    placeholder = "".join(['.' * len(chunk) for chunk in ct_chunks])
    
    # Start the replacement output line
    sys.stdout.write("  " + placeholder + "\r") 
    sys.stdout.flush()
    
    current_output = ""
    print("\nthe beast feeds:")
    
    # Now, replace the placeholder chunk by chunk with the actual ciphertext hex
    for i, hex_chunk in enumerate(ct_chunks):
        
        # Build the current partial ciphertext line
        current_output += hex_chunk
        
        # Replace the beginning of the placeholder string with the accumulated hex
        # Pad the rest with dots to maintain cursor position
        final_line = current_output + placeholder[len(current_output):]
        
        # Print the line, then carriage return to reset cursor
        sys.stdout.write(f"  {final_line}\r") 
        sys.stdout.flush()
        terminal_sleep(delay * 10)
    
    # Print the final result without carriage return
    print(f"  {current_output}") 
    
    # Print the token (The full process is complete)
    print(f"\nciphertext ({len(ct)} bytes):")
    for i, ch in enumerate(ct_chunks):
        print(f"  don't touch the keyboard {i:03d}: {ch}")
        terminal_sleep(delay*2) # Slower chunk print for clarity

    # --- END MODIFIED SECTION ---

    if gui: show_matplotlib_reveal(plaintext_bytes, ct, delay)
    blob = salt + nonce + ct
    token = base64.urlsafe_b64encode(blob).decode()
    print("\n encryption complete.")
    return token

def decrypt_visual(token: str, password: str, delay=0.05, gui=False) -> str:
    print("=== decrypting ===")
    blob = base64.urlsafe_b64decode(token)
    salt,nonce,ct = blob[:SALT_SIZE], blob[SALT_SIZE:SALT_SIZE+NONCE_SIZE], blob[SALT_SIZE+NONCE_SIZE:]
    print(f"salt in the wound: {salt.hex()}\nnonce: {nonce.hex()}\n")
    terminal_sleep(delay*4)
    print("deriving key...")
    key = derive_key(password,salt)
    print("key derived.\n")

    print("feeding ciphertext...")
    for i,ch in enumerate(nice_hex_chunks(ct)): print(f"  chunk {i:03d}: {ch}"); terminal_sleep(delay*6)
    aes = AESGCM(key)
    try: pt = aes.decrypt(nonce, ct, None)
    except Exception: sys.exit("wrong password or corrupted file.")
    print("cyphertext fed.\n")
    if gui: show_matplotlib_reveal(pt, ct, delay)
    return pt.decode()

# --- new file-based functions ---
def encrypt_file_visual(filepath: str, password: str, delay=0.05, gui=False):
    if not os.path.exists(filepath):
        sys.exit("file not found.")
    with open(filepath,"r",encoding="utf-8") as f: text=f.read()
    token = encrypt_visual(text, password, delay, gui)
    outpath = filepath + ".enc"
    with open(outpath,"w",encoding="utf-8") as f: f.write(token)
    print(f"now unreadable {outpath}")

def decrypt_file_visual(filepath: str, password: str, delay=0.05, gui=False):
    if not os.path.exists(filepath):
        sys.exit("encrypted file not found.")
    with open(filepath,"r",encoding="utf-8") as f: token=f.read().strip()
    plaintext = decrypt_visual(token, password, delay, gui)
    outpath = filepath.replace(".enc",".decrypted.txt")
    with open(outpath,"w",encoding="utf-8") as f: f.write(plaintext)
    print(f"the truth is revealed here: {outpath}")

# --- CLI interface ---
def main():
    p = argparse.ArgumentParser(description="Encrypt or decrypt text or files with visualization.")
    sub = p.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("encrypt", help="Encrypt plaintext")
    p1.add_argument("plaintext"); p1.add_argument("password")
    p1.add_argument("--delay",type=float,default=0.023); p1.add_argument("--gui",action="store_true")

    p2 = sub.add_parser("decrypt", help="Decrypt base64 token")
    p2.add_argument("token"); p2.add_argument("password")
    p2.add_argument("--delay",type=float,default=0.023); p2.add_argument("--gui",action="store_true")

    pf1 = sub.add_parser("encrypt-file", help="Encrypt a .txt file")
    pf1.add_argument("file"); pf1.add_argument("password")
    pf1.add_argument("--delay",type=float,default=0.023); pf1.add_argument("--gui",action="store_true")

    pf2 = sub.add_parser("decrypt-file", help="Decrypt a .enc file")
    pf2.add_argument("file"); pf2.add_argument("password")
    pf2.add_argument("--delay",type=float,default=0.023); pf2.add_argument("--gui",action="store_true")

    a = p.parse_args()
    if a.cmd=="encrypt": print(encrypt_visual(a.plaintext,a.password,a.delay,a.gui))
    elif a.cmd=="decrypt": print(decrypt_visual(a.token,a.password,a.delay,a.gui))
    elif a.cmd=="encrypt-file": encrypt_file_visual(a.file,a.password,a.delay,a.gui)
    elif a.cmd=="decrypt-file": decrypt_file_visual(a.file,a.password,a.delay,a.gui)

if __name__=="__main__":
    try: main()
    except KeyboardInterrupt:
        print("\nexcuse me?")
        sys.exit(130)