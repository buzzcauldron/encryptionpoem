import random
import time
import sys
import argparse
import re
# import uuid  <-- No longer needed

# --- Constants for Configuration ---

# 1. Lineation: Set your target syllables per line
TARGET_SYLLABLES_PER_LINE = 10

# 2. Speed: Delay for printing
PRINT_DELAY = 0.02

# 3. Bias: Define what we consider a "short" or "long" text (in characters)
REFERENCE_SHORT_LENGTH = 1000  # Texts shorter than this get the "short" bias
REFERENCE_LONG_LENGTH = 20000  # Texts longer than this get the "long" bias

# Define the keep-percentage ranges (1.0 = 100%)
# A 99% reduction ceiling means the MINIMUM to keep is 1% (0.01)

# For SHORT texts: bias toward 70%-85% reduction
SHORT_TEXT_MIN_KEEP = 0.15  # (85% reduction)
SHORT_TEXT_MAX_KEEP = 0.30  # (70% reduction)

# For LONG texts: bias toward 90%-99% reduction
LONG_TEXT_MIN_KEEP = 0.01   # (99% reduction)
LONG_TEXT_MAX_KEEP = 0.10   # (90% reduction)


def clean_text(text):
    """
    Converts text to lowercase and removes all special characters.
    Keeps only letters, numbers, and whitespace.
    """
    text = text.lower()
    text = re.sub(r'[^a-z0-9\s]', '', text) # Keep only letters, numbers, space
    text = re.sub(r'\s+', ' ', text).strip() # Collapse multiple spaces
    return text


def print_slowly(text, delay=PRINT_DELAY):
    """Prints text one character at a time to be human-readable."""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()


def estimate_syllables(word):
    """
    Estimates the number of syllables in a single word using a
    simple rule-based (heuristic) approach.
    """
    word = word.lower().strip()
    
    if not word or not re.search(r'[a-z]', word):
        return 0
        
    if len(word) <= 3:
        return 1
        
    if word.endswith('e'):
        if not (word.endswith('le') and re.search(r'[^aeiouy]le$', word)):
            word = word[:-1]

    vowel_groups = re.findall(r'[aeiouy]+', word)
    count = len(vowel_groups)
    
    if count == 0:
        return 1
        
    return count


def randomly_reduce_and_lineate_text(text, percentage_to_keep):
    """
    Reduces text by sampling words and formats them into
    lines based on a target syllable count.
    """
    words = text.split()

    if not words:
        return "(The source file was empty or had no words after cleaning.)"

    k = int(len(words) * percentage_to_keep)
    if k == 0 and len(words) > 0:
        k = 1  # Ensure we keep at least one word

    sampled_words = random.sample(words, k)
    
    all_lines = []
    current_line_words = []
    current_line_syllables = 0
    
    for word in sampled_words:
        word_syllables = estimate_syllables(word)
    
        if (current_line_syllables + word_syllables > TARGET_SYLLABLES_PER_LINE) and (current_line_syllables > 0):
            all_lines.append(' '.join(current_line_words))
            current_line_words = [word]
            current_line_syllables = word_syllables
        else:
            current_line_words.append(word)
            current_line_syllables += word_syllables
    
    if current_line_words:
         all_lines.append(' '.join(current_line_words))
    
    return '\n'.join(all_lines)


# --- Main execution ---
if __name__ == "__main__":

    # 1. Set up and parse arguments
    parser = argparse.ArgumentParser(
        description="Create a 'cut-up' poem from a source text file."
    )
    parser.add_argument(
        "filename", help="The path to the source .txt file"
    )
    args = parser.parse_args()

    # 2. Read the text from the specified file
    try:
        with open(args.filename, 'r', encoding='utf-8') as f:
            original_text = f.read()
    except FileNotFoundError:
        print(f"Error: The file '{args.filename}' was not found.")
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred while reading the file: {e}")
        sys.exit(1)

    # 3. Clean the text and get its length
    cleaned_text = clean_text(original_text)
    text_length = len(cleaned_text)

    # 4. Print the (un-cleaned) original text
    print("--- Original Text ---")
    print(original_text)
    print("\n" + "=" * 30 + "\n")
    time.sleep(1)  # Shorter pause

    # 5. Calculate biased reduction based on text length
    normalized_length = (text_length - REFERENCE_SHORT_LENGTH) / \
                        (REFERENCE_LONG_LENGTH - REFERENCE_SHORT_LENGTH)
    
    length_factor = max(0.0, min(1.0, normalized_length)) # Clamp between 0.0 and 1.0

    current_min_keep = (SHORT_TEXT_MIN_KEEP * (1 - length_factor)) + \
                       (LONG_TEXT_MIN_KEEP * length_factor)
                       
    current_max_keep = (SHORT_TEXT_MAX_KEEP * (1 - length_factor)) + \
                       (LONG_TEXT_MAX_KEEP * length_factor)
    
    # 6. Pick a random percentage from within the new biased range
    random_keep_percentage = random.uniform(current_min_keep, current_max_keep)
    reduction_percentage = (1 - random_keep_percentage) * 100

    # 7. Create the reduced and lineated text
    reduced_text = randomly_reduce_and_lineate_text(
        cleaned_text,
        percentage_to_keep=random_keep_percentage,
    )

    # 8. PRINT SLOWLY
    print(f"--- Reduced & Cleaned Text ({reduction_percentage:.0f}% reduction) ---")
    print_slowly(reduced_text) # This will print slowly to the screen

    # 9. --- MODIFIED FILE OUTPUT LOGIC ---
    
    # Get words from the cleaned text to use for the title
    source_words_list = cleaned_text.split()
    output_filename = "poem_output.txt" # Default fallback name

    if source_words_list: # Check if list is not empty
        # Pick a number of words (1 to 4)
        num_words = random.randint(1, 4)
        
        # Make sure we don't try to pick more words than exist
        num_words = min(num_words, len(source_words_list)) 
        
        # Randomly sample that many words
        title_words = random.sample(source_words_list, num_words)
        
        # Join with underscores and add .txt extension
        output_filename = '_'.join(title_words) + ".txt"

    # 10. Write the reduced text to the new file
    try:
        with open(output_filename, 'w', encoding='utf-8') as f:
            f.write(reduced_text)
        
        # This message now appears *after* the slow-print is finished
        print(f"\nSuccessfully saved poem to: {output_filename}")

    except Exception as e:
        print(f"\nAn error occurred while writing the output file: {e}")