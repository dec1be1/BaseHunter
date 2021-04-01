#!/usr/bin/env python3

import re
import argparse
from base64 import b64decode
from sys import stdin, exit

### FUNCTIONS ###

def is_base64(str):
    """
    return True is it is a base64 string or False if it is not
    """
    return b64_pattern.match(str, 0, len(str))

def is_text(data_b):
    try:
        data_b.decode()
        return True
    except UnicodeDecodeError:
        return False


### GLOBAL VARIABLES ###

b64_regex = "^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$"
b64_pattern = re.compile(b64_regex)
len_min = 5
len_max = 100


### MAIN FUNCTION ###

def main():

    parser = argparse.ArgumentParser(description="This script look for base64 strings and try to decode it.")
    parser.add_argument("-f", "--file", help="The path of the input file.", required=False)
    parser.add_argument("-i", "--stdin", help="This option makes the script read on stdin", required=False, action='store_true')
    parser.add_argument("-o", "--output", help="The path of the output file. Print to stdout if not specified.", required=False)
    args = parser.parse_args()

    file_path = args.file
    output_path = args.output
    STDIN = args.stdin

    # Check arguments
    if not file_path and not STDIN:
        print("[!] Error: You must give me some data. Bye!")
        exit(1)

    # Get input data
    if STDIN:
        data_b = stdin.buffer.read()
    else:
        with open(file_path, 'rb') as f:
            data_b = f.read()

    # Check if input is only unicode
    if is_text(data_b):
        data = data_b.decode()
    else:
        print("[!] Error: input data must be only unicode. Bye!")
        exit(1)

    # Split data and strip each lines
    data_lines = data.split("\n")
    for i in range(len(data_lines)):
        data_lines[i] = data_lines[i].strip()

    # Check for candidate
    for line in data_lines:
        line_len = len(line)
        for candidate_len in range(len_min, len_max+1):
            if (line_len - candidate_len) > 0:
                for i in range(line_len - candidate_len):
                    candidate = line[i:i+candidate_len].strip()
                    #print(candidate)
                    if is_base64(candidate) and len(candidate) >= candidate_len:
                        candidate_decoded = b64decode(candidate)
                        if is_text(candidate_decoded):
                            print(candidate_decoded.decode())


if __name__ == '__main__':
    main()
