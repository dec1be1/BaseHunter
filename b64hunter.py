#!/usr/bin/env python3

import argparse
from re import compile, match
from sys import stdin, exit

### FUNCTIONS ###

def is_base(base_pattern, str):
    """
    base_pattern is a compiled python3 regex.
    str is a string object.
    return True if the string match the base_pattern or False if it is not.
    """
    return base_pattern.match(str, 0, len(str))

def is_unicode(data_b):
    """
    data_b is a bytes object.
    """
    try:
        data_b.decode()
        return True
    except UnicodeDecodeError:
        return False

def get_decodefunction_and_basepattern(base):
    """
    base is a string ("64" for example).
    return a 2-tuple (decode_function, base_pattern).
    """
    if base == "64":
        from base64 import b64decode
        decode_function = b64decode
        base_regex = "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/][AQgw]==|[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=)?$"
    elif base == "16":
        decode_function = bytes.fromhex
        base_regex = "^([A-Fa-f0-9][A-Fa-f0-9])+$"
    elif base == "32":
        from base64 import b32decode
        decode_function = b32decode
        base_regex = "^(?:[A-Z2-7]{8})*(?:[A-Z2-7]{2}={6}|[A-Z2-7]{4}={4}|[A-Z2-7]{5}={3}|[A-Z2-7]{7}=)?$"
    else:
        print("[!] Error: Base {0} not found. Bye!".format(base))
        exit(1)
    return (decode_function, compile(base_regex))

def search_candidates(base_pattern, decode_f, data_lines, len_min, len_max):
    """
    data_lines is an array of strings.
    return an array of 2-tuples (line_number, candidate).
    """
    results = []
    li = 0
    for line in data_lines:
        li += 1
        line_len = len(line)
        for candidate_len in range(len_min, line_len+1):
            if len_min <= candidate_len <= len_max:
                i_max = line_len - candidate_len
                for i in range(i_max):
                    candidate = line[i:i+candidate_len+1].strip()
                    if is_base(base_pattern, candidate) and len(candidate) > 0:
                        candidate_decoded = decode_f(candidate)
                        if is_unicode(candidate_decoded):
                            results.append((li, candidate_decoded.decode()))
    return results

def consolidate(results):
    """
    result is a list object.
    return a consolidated list.
    """
    results_c = results.copy()
    for i in range(len(results)):
        for j in range(len(results)):
            if i != j:
                if results[i][1] in results[j][1]:
                    try:
                        results_c.remove(results[i])
                    except ValueError:
                        pass
    return results_c


### GLOBAL VARIABLES ###

default_base = "64"
default_minlen = 5
default_maxlen = 50


### MAIN FUNCTION ###

def main():

    parser = argparse.ArgumentParser(description="This script hunts baseXX strings in unicode data and try to decode it.")
    parser.add_argument("-f", "--file", help="The path of the input file.", required=False)
    parser.add_argument("-i", "--stdin", help="This option makes the script read on stdin", required=False, action='store_true')
    parser.add_argument("-n", "--minlen", help="The minimum length of base64 string to hunt. Default is {0}.".format(default_minlen), required=False, default=default_minlen)
    parser.add_argument("-x", "--maxlen", help="The maximum length of base64 string to hunt. Default is {0}.".format(default_maxlen), required=False, default=default_maxlen)
    parser.add_argument("-b", "--base", help="The base of string to hunt. Default is {0}.".format(default_base), required=False, default=default_base)
    args = parser.parse_args()

    file_path = args.file
    STDIN = args.stdin
    len_min = int(args.minlen)
    len_max = int(args.maxlen)
    base = args.base

    # Check arguments
    if not file_path and not STDIN:
        print("[!] Error: You must give me some data. Try \"--help\". Bye!")
        exit(1)

    # Base
    decode_function, base_pattern = get_decodefunction_and_basepattern(base)

    # Get input data
    if STDIN:
        data_b = stdin.buffer.read()
    else:
        with open(file_path, 'rb') as f:
            data_b = f.read()
    print("[+] Info: Input data loaded: {0} bytes.".format(len(data_b)))

    # Check if input is only unicode
    if not is_unicode(data_b):
        print("[!] Error: input data must be unicode only. Bye!")
        exit(1)

    data = data_b.decode()

    # Split data and strip each lines
    data_lines = data.split("\n")
    print("[+] Info: Input data contains {0} line(s).".format(len(data_lines)))
    for i in range(len(data_lines)):
        data_lines[i] = data_lines[i].strip()

    # Search for candidates
    print("[*] Info: Hunting base{0} strings (minlen: {1} / maxlen: {2})...".format(base, len_min, len_max))
    results = search_candidates(base_pattern, decode_function, data_lines, len_min, len_max)

    # Consolidate results
    print("[*] Info: Consolidating results...")
    results_c = consolidate(results)
    results.clear()

    # Print results
    if len(results_c) > 0:
        print("[+] Info: {0} base{1} strings found! Here are the decoded versions:".format(len(results_c), base))
        for r in results_c:
            print("  -> Line {0}: {1}".format(r[0], r[1]))
    else:
        print("[+] Info: base{0} strings not found. Bye!".format(base))

    exit(0)

if __name__ == '__main__':
    main()
