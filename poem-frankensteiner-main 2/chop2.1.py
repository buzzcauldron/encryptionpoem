import random
import time
import sys
import argparse
import re  # <-- Import regular expressions for cleaning

# --- Constants for Configuration ---

# 1. Lineation: Lines will be a fixed length
WORDS_PER_LINE = 6

# 2. Speed: Faster delay for printing
PRINT_DELAY = 0.02

# 3. Bias: Define what we consider a "short" or "long" text (in characters)
#    This will be used to bias the reduction percentage.
REFERENCE_SHORT_LENGTH = 1000  # Texts shorter than this get the "short" bias
REFERENCE_LONG_LENGTH = 20000  # Texts longer than this get the "long" bias

# Define the keep-percentage ranges (1.0 = 100%)
# A 99% reduction ceiling means the MINIMUM to keep is 1% (0.01)

# For SHORT texts: bias toward 70%-85% reduction
SHORT_TEXT_MIN_KEEP = 0.15  # (85% reduction)
SHORT_TEXT_MAX_KEEP = 0.30  # (70% reduction)

# For LONG texts: bias toward 90%-99% reduction
LONG_TEXT_MIN_KEEP = 0.01   # (99% reduction) - This is your new ceiling
LONG_TEXT_MAX_KEEP = 0.10   # (90% reduction)


def clean_text(text):
    """
    Converts text to lowercase and removes all special characters.
    Keeps only letters, numbers, and whitespace.
    """
    text = text.lower()
    # Remove any character that is not a-z, 0-9, or whitespace (\s)
    text = re.sub(r'[^a-z0-9\s]', '', text)
    # Optional: collapse multiple spaces into one
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def print_slowly(text, delay=PRINT_DELAY):
    """Prints text one character at a time to be human-readable."""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()


def randomly_reduce_and_lineate_text(text, percentage_to_keep):
    """
    Reduces the text by sampling words and formats them into
    regular lines of a fixed word count.
    """
    words = text.split()

    if not words:
        return "(The source file was empty or had no words after cleaning.)"

    k = int(len(words) * percentage_to_keep)
    if k == 0 and len(words) > 0:
        k = 1  # Ensure we keep at least one word

    sampled_words = random.sample(words, k)

    lineated_text_lines = []
    
    i = 0
    while i < len(sampled_words):
        # Get the slice of words for this line (fixed length)
        line_words = sampled_words[i : i + WORDS_PER_LINE]
        
        lineated_text_lines.append(' '.join(line_words))
        
        # Move the index forward by the fixed line length
        i += WORDS_PER_LINE

    return '\n'.join(lineated_text_lines)

import re

# --- BUILDING BLOCK 1: The Syllable Counter ---
# You need this function available to the main function.

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


# --- BUILDING BLOCK 2: The Function to Modify ---
# Replace your old function with this template.

def randomly_reduce_and_lineate_text(text, percentage_to_keep):
    """
    Reduces the text by sampling words and formats them into
    lines based on a target syllable count.
    """
    # --- This part is the same as before ---
    words = text.split()

    if not words:
        return "(The source file was empty or had no words after cleaning.)"

    k = int(len(words) * percentage_to_keep)
    if k == 0 and len(words) > 0:
        k = 1  # Ensure we keep at least one word

    sampled_words = random.sample(words, k)
    
    # --- This is the new logic you would write ---
    #
    # 1. Set your syllable target
    TARGET_SYLLABLES_PER_LINE = 10  # (Or 6, 12, etc.)
    #
    # 2. Initialize variables
    all_lines = []
    current_line_words = []
    current_line_syllables = 0
    #
    # 3. Loop through every word in sampled_words
    for word in sampled_words:
    #
    #     # 4. Count syllables for the new word
         word_syllables = estimate_syllables(word)
    #
    #     # 5. Check if adding this word goes OVER the target
    #     #    (But don't break if the line is empty)
         if (current_line_syllables + word_syllables > TARGET_SYLLABLES_PER_LINE) and (current_line_syllables > 0):
    #
    #         # a) If it does, finalize the current line
             all_lines.append(' '.join(current_line_words))
    #         
    #         # b) Start a new line with the current word
             current_line_words = [word]
             current_line_syllables = word_syllables
    #
         else:
    #         # 6. If it doesn't go over, just add the word
             current_line_words.append(word)
             current_line_syllables += word_syllables
    #
    # 7. After the loop, add the last remaining line
    if current_line_words:
         all_lines.append(' '.join(current_line_words))
    #
    # 8. Return the final result
    return '\n'.join(all_lines)
    #
    # --- End of new logic ---

    # For now, return a placeholder so the script doesn't crash
    # while you work on it.
#    return "This function is not yet implemented."

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
    
    # Normalize length from 0.0 (short) to 1.0 (long)
    normalized_length = (text_length - REFERENCE_SHORT_LENGTH) / \
                        (REFERENCE_LONG_LENGTH - REFERENCE_SHORT_LENGTH)
    
    # Clamp the factor between 0.0 and 1.0
    length_factor = max(0.0, min(1.0, normalized_length))

    # Linearly interpolate between the short and long ranges
    # (1 - factor) * short_val + factor * long_val
    current_min_keep = (SHORT_TEXT_MIN_KEEP * (1 - length_factor)) + \
                       (LONG_TEXT_MIN_KEEP * length_factor)
                       
    current_max_keep = (SHORT_TEXT_MAX_KEEP * (1 - length_factor)) + \
                       (LONG_TEXT_MAX_KEEP * length_factor)
    
    # --- End of bias logic ---

    # 6. Pick a random percentage from within the new biased range
    random_keep_percentage = random.uniform(current_min_keep, current_max_keep)
    reduction_percentage = (1 - random_keep_percentage) * 100

import re

def estimate_syllables(word):
    """
    Estimates the number of syllables in a single word using a
    simple rule-based (heuristic) approach.
    """
    word = word.lower().strip()
    
    # Handle empty strings or non-alphabetic words
    if not word or not re.search(r'[a-z]', word):
        return 0
        
    # --- Special Cases for very short words ---
    # (These rules are simple and effective for common words)
    if len(word) <= 3:
        return 1
        
    # --- Core Vowel-Counting Logic ---
    
    # 1. Remove the silent 'e' at the end (e.g., 'like' -> 'lik')
    #    but NOT if the word ends in 'le' and the letter before
    #    it is a consonant (e.g., 'table', 'apple')
    if word.endswith('e'):
        if not (word.endswith('le') and re.search(r'[^aeiouy]le$', word)):
            word = word[:-1]

    # 2. Find all continuous groups of vowels
    vowel_groups = re.findall(r'[aeiouy]+', word)
    
    # 3. The number of vowel groups is our base count
    count = len(vowel_groups)
    
    # 4. If our rules made the count 0, it's at least 1
    if count == 0:
        return 1
        
    return count


    # 7. Create the reduced and lineated text from the *cleaned* text
    reduced_text = randomly_reduce_and_lineate_text(
        cleaned_text,
        percentage_to_keep=random_keep_percentage,
        )

    # 8. Show the reduction
    print(f"--- Reduced & Cleaned Text ({reduction_percentage:.0f}% reduction) ---")
    print_slowly(reduced_text)