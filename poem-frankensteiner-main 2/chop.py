import random
import time
import sys

def print_slowly(text, delay=0.01):
    """Prints text one character at a time to be human-readable."""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    # The text already contains newlines, so we don't add another
    # print() here, but we will print one final newline after all lines.
    print() 

def randomly_reduce_and_lineate_text(text, percentage_to_keep):
    """
    Reduces the text by sampling words and formats them into
    lines with a random word count.
    """
    words = text.split()
    
    # Calculate the number of words to keep
    k = int(len(words) * percentage_to_keep)
    
    # Randomly sample 'k' words from the original list
    sampled_words = random.sample(words, k)
    
    # --- New Lineation Logic ---
    lineated_text_lines = []
    min_words_per_line = 3  # Approximating a short poetic line
    max_words_per_line = 7  # Approximating a longer poetic line
    
    i = 0
    while i < len(sampled_words):
        # Determine a random length for this line
        line_length = random.randint(min_words_per_line, max_words_per_line)
        
        # Get the slice of words for this line (e.g., words[0:5])
        line_words = sampled_words[i : i + line_length]
        
        # Join them into a single string and add to our list
        lineated_text_lines.append(' '.join(line_words))
        
        # Move the index forward for the next iteration
        i += line_length
        
    # Join all the individual lines with a newline character
    return '\n'.join(lineated_text_lines)

# --- Main execution ---
if __name__ == "__main__":
    original_text = (
        "This is the original source text file. "
        "It contains several sentences that will be processed. "
        "The goal is to demonstrate text manipulation in Python. "
        "We will first print this entire text. "
        "Then, we will show a randomly reduced version. "
        "This version will be broken into many smaller lines "
        "to see how the new formatting looks."
    )
    
    # 1. Print the whole text
    print("--- Original Text ---")
    print(original_text)
    print("\n" + "="*30 + "\n")
    
    time.sleep(2) # Pause

    # 2. Set random reduction percentage
    min_keep_percent = 0.03 # 97% reduction
    max_keep_percent = 0.30 # 70% reduction
    random_keep_percentage = random.uniform(min_keep_percent, max_keep_percent)
    reduction_percentage = (1 - random_keep_percentage) * 100
    
    # 3. Create the reduced and lineated text
    reduced_text = randomly_reduce_and_lineate_text(
        original_text, 
        percentage_to_keep=random_keep_percentage
    )
    
    # 4. Show the reduction at a speed visible to humans
    print(f"--- Randomly Reduced Text ({reduction_percentage:.0f}% reduction) ---")
    print_slowly(reduced_text, delay=0.05)