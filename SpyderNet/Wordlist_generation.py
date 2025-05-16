import sys
import itertools
import argparse
import os
from typing import List, Optional

# Default character sets
DEF_LOWER = "abcdefghijklmnopqrstuvwxyz"
DEF_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DEF_NUM = "0123456789"
DEF_SYM = "!@#$%^&*()-_+=~`[]{}|\\:;\"'<>,.?/ "

# Maximum string length (to prevent excessive memory usage)
MAX_STRING = 128

class ForgeOptions:
    def __init__(self, min_len: int, max_len: int, charset: str = DEF_LOWER, 
                 upper: str = DEF_UPPER, numbers: str = DEF_NUM, symbols: str = DEF_SYM,
                 pattern: Optional[str] = None, start: Optional[str] = None,
                 end: Optional[str] = None, literal: Optional[str] = None,
                 output: Optional[str] = None, permute: bool = False,
                 permute_words: Optional[List[str]] = None):
        self.min_len = min_len
        self.max_len = max_len
        self.charset = charset
        self.upper = upper
        self.numbers = numbers
        self.symbols = symbols
        self.pattern = pattern
        self.start = start
        self.end = end
        self.literal = literal or ('-' * max_len if pattern else '')
        self.output = output
        self.permute = permute
        self.permute_words = permute_words or []
        
        # Validate inputs
        if max_len < min_len:
            raise ValueError("Max length must be >= min length")
        if max_len > MAX_STRING:
            raise ValueError(f"Max length must be <= {MAX_STRING}")
        if pattern and (min_len != max_len or len(pattern) != max_len):
            raise ValueError("Pattern length must equal min/max length")
        if literal and len(literal) != len(pattern or ''):
            raise ValueError("Literal string length must match pattern")
        if start and len(start) != min_len:
            raise ValueError("Start string length must equal min length")
        if end and len(end) != max_len:
            raise ValueError("End string length must equal max length")
        if start and end and start > end:
            raise ValueError("End string must be >= start string")
        if permute and start:
            raise ValueError("Permute mode (-p) cannot be used with start string (-s)")

def remove_duplicates(s: str) -> str:
    """Remove duplicate characters from a string, preserving order."""
    seen = set()
    return ''.join(c for c in s if not (c in seen or seen.add(c)))

def generate_pattern_string(s: str, options: ForgeOptions) -> str:
    """Apply pattern to a string, respecting literal characters."""
    if not options.pattern:
        return s
    result = []
    for i, (p, c) in enumerate(zip(options.pattern, s)):
        if options.literal[i] == p:
            result.append(p)
        elif p in '@,%^' and options.literal[i] != p:
            result.append(c)
        else:
            result.append(options.pattern[i])
    return ''.join(result)

def forge_combinations(options: ForgeOptions, output_file):
    """Generate wordlist using character set combinations."""
    charset = options.charset
    if options.pattern:
        # Pattern mode: generate combinations for placeholders
        placeholders = []
        charsets = []
        for i, c in enumerate(options.pattern):
            if options.literal[i] == c:
                continue
            if c == '@':
                placeholders.append(i)
                charsets.append(options.charset)
            elif c == ',':
                placeholders.append(i)
                charsets.append(options.upper)
            elif c == '%':
                placeholders.append(i)
                charsets.append(options.numbers)
            elif c == '^':
                placeholders.append(i)
                charsets.append(options.symbols)
        
        start_idx = [0] * len(placeholders)
        if options.start:
            for i, pos in enumerate(placeholders):
                c = options.start[pos]
                if c in charsets[i]:
                    start_idx[i] = charsets[i].index(c)
        
        for length in range(options.min_len, options.max_len + 1):
            if length != len(options.pattern):
                continue
            for comb in itertools.product(*charsets, repeat=1):
                s = list(options.pattern)
                for i, pos in enumerate(placeholders):
                    s[pos] = comb[i]
                s = ''.join(s)
                if options.start and s < options.start:
                    continue
                if options.end and s > options.end:
                    break
                print(s, file=output_file)
    else:
        # Standard mode: generate all combinations
        for length in range(options.min_len, options.max_len + 1):
            for comb in itertools.product(charset, repeat=length):
                s = ''.join(comb)
                if options.start and s < options.start:
                    continue
                if options.end and s > options.end:
                    break
                print(s, file=output_file)

def permute(options: ForgeOptions, output_file):
    """Generate permutations of words or characters."""
    words = options.permute_words
    if options.pattern:
        # Permute with pattern
        placeholders = []
        charsets = []
        for i, c in enumerate(options.pattern):
            if options.literal[i] == c:
                continue
            if c == '@':
                placeholders.append(i)
                charsets.append(options.charset)
            elif c == ',':
                placeholders.append(i)
                charsets.append(options.upper)
            elif c == '%':
                placeholders.append(i)
                charsets.append(options.numbers)
            elif c == '^':
                placeholders.append(i)
                charsets.append(options.symbols)
        
        for perm in itertools.permutations(words):
            base = ''.join(perm)
            for comb in itertools.product(*charsets, repeat=1):
                s = list(options.pattern)
                word_idx = 0
                for i, pos in enumerate(placeholders):
                    s[pos] = comb[i]
                for i, c in enumerate(s):
                    if c not in '@,%^' or options.literal[i] == c:
                        continue
                    s[i] = base[word_idx]
                    word_idx += 1
                s = ''.join(s)
                print(s, file=output_file)
    else:
        # Simple permutations
        for perm in itertools.permutations(words):
            print(''.join(perm), file=output_file)

def parse_args() -> ForgeOptions:
    parser = argparse.ArgumentParser(description="Forge wordlist generator")
    parser.add_argument('min', type=int, help="Minimum length")
    parser.add_argument('max', type=int, help="Maximum length")
    parser.add_argument('charset', nargs='?', default=DEF_LOWER, help="Character set")
    parser.add_argument('--upper', default=DEF_UPPER, help="Uppercase charset")
    parser.add_argument('--numbers', default=DEF_NUM, help="Numeric charset")
    parser.add_argument('--symbols', default=DEF_SYM, help="Symbol charset")
    parser.add_argument('-o', '--output', help="Output file")
    parser.add_argument('-t', '--pattern', help="Pattern (e.g., @@god@@@@)")
    parser.add_argument('-s', '--start', help="Start string")
    parser.add_argument('-e', '--end', help="End string")
    parser.add_argument('-l', '--literal', help="Literal characters for pattern")
    parser.add_argument('-p', '--permute', nargs='*', help="Permute words or single string")
    
    args = parser.parse_args()
    
    permute_words = None
    permute = bool(args.permute is not None)
    if permute:
        if len(args.permute) == 1:
            permute_words = list(args.permute[0])
        else:
            permute_words = args.permute
    
    return ForgeOptions(
        min_len=args.min,
        max_len=args.max,
        charset=remove_duplicates(args.charset),
        upper=remove_duplicates(args.upper),
        numbers=remove_duplicates(args.numbers),
        symbols=remove_duplicates(args.symbols),
        pattern=args.pattern,
        start=args.start,
        end=args.end,
        literal=args.literal,
        output=args.output,
        permute=permute,
        permute_words=permute_words
    )

def main():
    options = parse_args()
    
    # Set up output file or use stdout
    if options.output:
        output_file = open(options.output, 'w')
    else:
        output_file = sys.stdout
    
    try:
        # Generate wordlist
        if options.permute:
            permute(options, output_file)
        else:
            forge_combinations(options, output_file)
    
    finally:
        if options.output:
            output_file.close()

if __name__ == "__main__":
    main()