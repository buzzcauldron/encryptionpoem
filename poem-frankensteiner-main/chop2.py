import random
import time
import sys
import argparse  # <-- Import the new module

def print_slowly(text, delay=0.01):
    """Prints text one character at a time to be human-readable."""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print() 

def randomly_reduce_and_lineate_text(text, percentage_to_keep):
    """
    Reduces the text by sampling words and formats them into
    lines with a random word count.
    """
    words = text.split()
    
    # Handle case where file is empty or has no words
    if not words:
        return "(The source file was empty.)"
        
    k = int(len(words) * percentage_to_keep)
    # Ensure k is at least 1 if there are any words
    if k == 0 and len(words) > 0:
        k = 1
        
    sampled_words = random.sample(words, k)
    
    lineated_text_lines = []
    min_words_per_line = 3
    max_words_per_line = 7
    
    i = 0
    while i < len(sampled_words):
        line_length = random.randint(min_words_per_line, max_words_per_line)
        line_words = sampled_words[i : i + line_length]
        lineated_text_lines.append(' '.join(line_words))
        i += line_length
        
    return '\n'.join(lineated_text_lines)

# --- Main execution ---
if __name__ == "__main__":
    
    # --- MODIFICATION IS HERE ---
    
    # 1. Set up the argument parser
    parser = argparse.ArgumentParser(
        description="Create a 'cut-up' poem from a source text file."
    )
    # Add one positional argument: the filename
    parser.add_argument(
        "filename", 
        help="The path to the source .txt file"
    )
    
    # Parse the arguments from the command line
    args = parser.parse_args()

    # 2. Read the text from the specified file
    try:
        # Use encoding='utf-8' for broad compatibility
        with open(args.filename, 'r', encoding='utf-8') as f:
            original_text = f.read()
    except FileNotFoundError:
        print(f"Error: The file '{args.filename}' was not found.")
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred while reading the file: {e}")
        sys.exit(1)

    # --- END MODIFICATION ---

    # 3. Print the whole text
    print("--- Original Text ---")
    print(original_text)
    print("\n" + "="*30 + "\n")
    
    time.sleep(2) # Pause

    # 4. Set random reduction percentage
    min_keep_percent = 0.03 # 97% reduction
    max_keep_percent = 0.30 # 70% reduction
    random_keep_percentage = random.uniform(min_keep_percent, max_keep_percent)
    reduction_percentage = (1 - random_keep_percentage) * 100
    
    # 5. Create the reduced and lineated text
    reduced_text = randomly_reduce_and_lineate_text(
        original_text, 
        percentage_to_keep=random_keep_percentage
    )
    
    # 6. Show the reduction at a speed visible to humans
    print(f"--- Randomly Reduced Text ({reduction_percentage:.0f}% reduction) ---")
    print_slowly(reduced_text, delay=0.05)