from string import printable, ascii_letters
import sys
import re
import argparse
from argparse import RawTextHelpFormatter

def shellquote(s):
    return "'" + s.replace("\\","\\\\").replace("\"","\\\"").replace("'", "\\'").replace("`", "\\`") + "'"


description = """
Rewrite input in XOR form to bypass restrictions.

Example: 
> python xorer.py 'Tesst' -b '[A-Zb-z]' -s '.'
>> Output: ('4' ^ '\\`').('8' ^ ']').('3' ^ '@').('4' ^ '@')

> php -r "echo ('4' ^ '\\`').('8' ^ ']').('3' ^ '@').('3' ^ '@').('4' ^ '@');"
>> Output: Tesst
"""

if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog="XORer", description=description, formatter_class=RawTextHelpFormatter)
    parser.add_argument('input', help='Input to XOR.')
    parser.add_argument('-b', '--banned', action='store', default="", help='Regex for exclude banned chars from the output.')
    parser.add_argument('-s', '--separator', action='store', default="+", help='Char-to-char XOR separator.')
    args= parser.parse_args()

    input_string = args.input
    banned = args.banned if len(args.banned) > 0 else ""
    separator = args.separator if len(args.separator) > 0 else "+"
    
    charset = printable[:-6]
    banned = re.compile(banned)
    alphabet = {}
    
    for letter in ascii_letters:
        if not banned.match(letter):
            alphabet[letter] = letter
            continue
        for i in charset:
            if banned.match(i):
                continue
            for j in charset:
                if banned.match(j):
                    continue
                tmp = ord(i) ^ ord(j)
                if(chr(tmp) == letter):
                    alphabet[letter] = (i, j)
                    break
            if letter in alphabet.keys():
                break
    
    output_string = []
    for c in input_string:
        if c in alphabet.keys() and type(alphabet[c]) is tuple:
            (s1, s2) = alphabet[c]
            output_string.append(f"({shellquote(s1)} ^ {shellquote(s2)})")
        else:
            output_string.append(f"({shellquote(c)})")
    
    print(separator.join(output_string))
