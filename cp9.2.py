#!/usr/bin/env python3
"""
cp9.2.py — now supports file encryption/decryption with configurable print delay
---------------------------------------------------------
Encrypt text or .txt files with human-visible visualization.
NOTE: This version uses an INSECURE XOR cipher for visual demonstration purposes.
      It now also randomizes the line order during encryption.
      Added --print-delay parameter to control printing animation speed.

Examples:
  # Encrypt plaintext with slow printing
  python cp9.2.py encrypt "Roses are red, Violets are blue.\nSugar is sweet, And so are you." mypassword --print-delay 0.1

  # Encrypt file with custom print delay
  python cp9.2.py encrypt-file poem.txt mypassword --print-delay 0.05

  # Decrypt file
  python cp9.2.py decrypt-file poem.txt.enc mypassword --print-delay 0.01
"""

import argparse, base64, os, sys, threading, time
from typing import Optional
import random

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
SALT_SIZE = 0
NONCE_SIZE = 0
KDF_ITERATIONS = 0
KEY_LEN = 0
SEPARATOR = b'|' # Separator for map and data in the blob

# --- helpers ---
def derive_key(password: str, salt: bytes = b'', iterations: int = 0) -> bytes:
    """Uses the password directly as the key."""
    return password.encode("utf-8")

def xor_crypt(data: bytes, key: bytes) -> bytes:
    """Performs XOR operation using a repeating key."""
    output = bytearray()
    key_len = len(key)
    for i, byte in enumerate(data):
        output.append(byte ^ key[i % key_len])
    return bytes(output)

def terminal_sleep(delay: float):
    try:
        sys.stdout.flush() 
        time.sleep(delay)
    except KeyboardInterrupt:
        raise

# Matplotlib visualization (Unchanged, uses XOR output)
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
def encrypt_visual(plaintext: str, password: str, print_delay=0.001, gui=False) -> str:
    print("=== **ENCRYPTING** ===")
    
    key = derive_key(password)
    print(f"**key derived**: '{key.decode()}' (Length: {len(key)})")
    terminal_sleep(print_delay*4)

    # 1. Split and Prepare
    # FIX: Use splitlines(keepends=True) to preserve newlines
    plaintext_lines = plaintext.splitlines(keepends=True)
    num_lines = len(plaintext_lines)
    
    # List of (index, plaintext_line_bytes)
    indexed_lines = [(i, line.encode("utf-8")) for i, line in enumerate(plaintext_lines)]
    
    # 2. Encrypt Individually and Store Lengths
    # 3. Shuffle (This determines the order of visualization)
    random.shuffle(indexed_lines)
    
    # --- MODIFIED: Print Statements and Loop Logic ---
    print(f"\n**you wrote** ({len(plaintext_lines)} lines):")
    
    # Print original plaintext lines
    for line in plaintext_lines:
        # Print the line directly, with indentation. 
        # sys.stdout.write is used because 'line' already contains its own newline.
        sys.stdout.write(f"  {line}") 
    terminal_sleep(print_delay * 10 * max(1, num_lines)) # Avoid 0 delay delay
    
    print("\n**the beast feeds** :")
    
    # Placeholder list for the lines currently being displayed in the terminal
    # Initialize with the original plaintext lines (decoded 'latin-1' is safe for byte arrays)
    current_display_lines = [line.decode('latin-1') for _, line in indexed_lines] 
    
    # List to hold the final encrypted bytes in shuffled order
    shuffled_ct_bytes = []
    
    # Handle case with 0 lines (empty file)
    if num_lines == 0:
        print("  (empty input)")
    
    for shuffled_idx, (original_idx, pt_bytes) in enumerate(indexed_lines):
        
        ct_bytes = xor_crypt(pt_bytes, key)
        shuffled_ct_bytes.append(ct_bytes)

        print(f"\n farewell {original_idx}):")
        
        # Get the character length of the line being encrypted
        line_len = len(ct_bytes)
        
        # Overwrite the line-slot in the display array with the plaintext before encrypting
        current_display_lines[shuffled_idx] = pt_bytes.decode('latin-1')
        
        # Print the current state of all lines (shuffled order)
        for line_out in current_display_lines:
            # Write line by line, but don't add an extra newline if it already has one
            sys.stdout.write(f"  {line_out.rstrip(os.linesep)}\n")
        
        # Move cursor back up to the top of the block
        sys.stdout.write(f"\033[{num_lines}A") 
        # Move cursor down to the line we are encrypting
        if shuffled_idx > 0:
            sys.stdout.write(f"\033[{shuffled_idx}B")

        # Move cursor to the start of the line (with \r) and indent
        sys.stdout.write(f"\r  ")
        
        # Perform character-by-character replacement on the target line
        line_output_array = bytearray(pt_bytes)
        
        for i in range(line_len):
            line_output_array[i] = ct_bytes[i]
            
            # Print the partially encrypted output, then carriage return
            line_out = line_output_array.decode('latin-1').rstrip(os.linesep)
            sys.stdout.write(f"\r  {line_out}")
            terminal_sleep(print_delay * 2)
            
        # Update the display array with the final encrypted line
        current_display_lines[shuffled_idx] = line_output_array.decode('latin-1')

        # Print the final encrypted line without carriage return to confirm the step
        final_line_out = line_output_array.decode('latin-1').rstrip(os.linesep)
        sys.stdout.write(f"\r  {final_line_out}\n")
        
        # Print remaining lines (move cursor back down and print rest of the lines)
        for i in range(shuffled_idx + 1, num_lines):
             sys.stdout.write(f"  {current_display_lines[i].rstrip(os.linesep)}\n")
        
        terminal_sleep(print_delay * 10)
        
    print("\n\n") # Clear space below the final output
    # --- END MODIFIED SECTION ---

    # Reconstruct the token: Map (Original Index), Separator, Encrypted Data
    
    # Create the map of original indices (e.g., [2, 0, 1] if line 2 came first)
    shuffle_map = [original_idx for original_idx, _ in indexed_lines]
    map_str = ','.join(map(str, shuffle_map))
    map_bytes = map_str.encode('utf-8')
    
    # Concatenate all encrypted bytes
    ct_blob = b''.join(shuffled_ct_bytes)
    
    final_blob = map_bytes + SEPARATOR + ct_blob
    
    if gui: show_matplotlib_reveal(plaintext.encode(), final_blob, print_delay)
    
    token = base64.urlsafe_b64encode(final_blob).decode()
    print("\n**a dream remains**.")
    return token

def decrypt_visual(token: str, password: str, print_delay=0.001, gui=False) -> str:
    print("=== **i unmask** ===")
    
    try:
        final_blob = base64.urlsafe_b64decode(token)
    except Exception:
        sys.exit("corruption is permanent. release attachment.")
    
    # Split the blob: map | data
    if SEPARATOR not in final_blob:
        sys.exit("wrong password or corrupted file: missing data map.")

    map_bytes, ct_blob = final_blob.split(SEPARATOR, 1)
    
    try:
        #FIX: Handle case where map_str is empty (from an empty input file)
        map_str = map_bytes.decode('utf-8')
        if not map_str:
            shuffle_map = []
        else:
            shuffle_map = list(map(int, map_str.split(',')))
    except ValueError:
        sys.exit("corruption is permanent. release all attachment.")
        
    key = derive_key(password)
    print(f"**key derived**.")
    terminal_sleep(print_delay*4)
    
    print("**feeding ciphertext**...")
    terminal_sleep(print_delay*10)

    # Decrypt the entire blob 
    pt_blob = xor_crypt(ct_blob, key)
    
    # FIX: Use splitlines(keepends=True) to correctly split the blob
    pt_lines = pt_blob.decode('utf-8', errors='ignore').splitlines(keepends=True)
    
    # Check if the number of lines found matches the shuffle map
    if len(pt_lines) != len(shuffle_map):
        # FIX: Provide a useful error message instead of 'pass'
        sys.exit(f"corruption is permanent. release all attachment. (map says {len(shuffle_map)}, your path has {len(pt_lines)})")
        
    # Create the final plaintext array indexed by original position
    final_plaintext_lines = [None] * len(shuffle_map)
    
    try:
        # Reorder the decrypted lines based on the shuffle map
        for i, original_idx in enumerate(shuffle_map):
            final_plaintext_lines[original_idx] = pt_lines[i]
            
        # FIX: Join with an empty string, as lines already have newlines
        final_plaintext_str = ''.join(final_plaintext_lines)
    except Exception:
        sys.exit("corruption is permanent. release all attachment.")
    
    
    # --- Visualization (Simplified) ---
    print(f"\n**ciphertext** ({len(ct_blob)} bytes) -> **plaintext**:")
    
    # Re-encode the final plaintext for visualization
    pt_visual_bytes = final_plaintext_str.encode('utf-8')
    
    # Visualize the full process as a single unit (due to complexity of line manipulation)
    current_output = bytearray(ct_blob)
    
    print("\n**the truth is revealed** (reordering lines):")
    
    # Visualize the full decryption, character by character
    max_len = max(len(pt_visual_bytes), len(current_output))
    # Pad output array if plaintext is longer (e.g., key added chars)
    current_output.extend(b' ' * (max_len - len(current_output))) 
    
    for i in range(max_len):
        if i < len(pt_visual_bytes):
            current_output[i] = pt_visual_bytes[i]
        else:
            # If plaintext was shorter, erase remaining ciphertext
            current_output[i] = b' '[0] 
            
        line_out = current_output.decode('latin-1')
        sys.stdout.write(f"  {line_out}\r") 
        terminal_sleep(print_delay) 

    # Final result without carriage return
    print(f"  {pt_visual_bytes.decode('utf-8')}") 
    
    print("decryption successful.\n")
    if gui: show_matplotlib_reveal(pt_visual_bytes, ct_blob, print_delay)
    return final_plaintext_str

# --- new file-based functions (Print delay parameter for controlling printing speed) ---
def encrypt_file_visual(filepath: str, password: str, print_delay=0.001, gui=False):
    if not os.path.exists(filepath):
        sys.exit("file not found.")
    with open(filepath,"r",encoding="utf-8") as f: text=f.read()
    token = encrypt_visual(text, password, print_delay, gui)
    outpath = filepath + ".enc"
    with open(outpath,"w",encoding="utf-8") as f: f.write(token)
    print(f"**now unreadable along this path** {outpath}")

def decrypt_file_visual(filepath: str, password: str, print_delay=0.01, gui=False):
    if not os.path.exists(filepath):
        sys.exit("encrypted file not found.")
    with open(filepath,"r",encoding="utf-8") as f: token=f.read().strip()
    plaintext = decrypt_visual(token, password, print_delay, gui)
    outpath = filepath.replace(".enc",".decrypted.txt")
    if outpath == filepath: # Avoid overwriting if .enc wasn't present
        outpath = filepath + ".decrypted.txt"
    with open(outpath,"w",encoding="utf-8") as f: f.write(plaintext)
    print(f"**the truth is revealed here**: {outpath}")

# --- CLI interface with print-delay parameter ---
def main():
    p = argparse.ArgumentParser(description="Encrypt or decrypt text or files with visualization and configurable print delay.")
    sub = p.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("encrypt", help="Encrypt plaintext")
    p1.add_argument("plaintext"); p1.add_argument("password")
    p1.add_argument("--print-delay", type=float, default=0.01, 
                    help="Delay in seconds between print animations (higher = slower printing)")
    p1.add_argument("--gui", action="store_true")

    p2 = sub.add_parser("decrypt", help="Decrypt base64 token")
    p2.add_argument("token"); p2.add_argument("password")
    p2.add_argument("--print-delay", type=float, default=0.0023,
                    help="Delay in seconds between print animations (higher = slower printing)")
    p2.add_argument("--gui", action="store_true")

    pf1 = sub.add_parser("encrypt-file", help="Encrypt a .txt file")
    pf1.add_argument("file"); pf1.add_argument("password")
    pf1.add_argument("--print-delay", type=float, default=0.023,
                     help="Delay in seconds between print animations (higher = slower printing)")
    pf1.add_argument("--gui", action="store_true")

    pf2 = sub.add_parser("decrypt-file", help="Decrypt a .enc file")
    pf2.add_argument("file"); pf2.add_argument("password")
    pf2.add_argument("--print-delay", type=float, default=0.0023,
                     help="Delay in seconds between print animations (higher = slower printing)")
    pf2.add_argument("--gui", action="store_true")

    a = p.parse_args()
    if a.cmd=="encrypt": print(encrypt_visual(a.plaintext, a.password, a.print_delay, a.gui))
    elif a.cmd=="decrypt": print(decrypt_visual(a.token, a.password, a.print_delay, a.gui))
    elif a.cmd=="encrypt-file": encrypt_file_visual(a.file, a.password, a.print_delay, a.gui)
    elif a.cmd=="decrypt-file": decrypt_file_visual(a.file, a.password, a.print_delay, a.gui)

if __name__=="__main__":
    try: main()
    except KeyboardInterrupt:
        print("\n**excuse me?**")
        sys.exit(130)


