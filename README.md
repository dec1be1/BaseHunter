BaseHunter
==========

A tool to look for base 16, 32 or 64 strings in raw unicode data and try to
decode them. If the decoded strings are unicode, they are printed to stdout.

Usage :
```
$ ./basehunter.py --help
usage: basehunter.py [-h] [-f FILE] [-i] [-n MINLEN] [-x MAXLEN] [-b BASE]

This script hunts baseXX encoded strings in unicode data and try to decode them.

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  The path of the input file.
  -i, --stdin           This option makes the script to read data on stdin
  -n MINLEN, --minlen MINLEN
                        The minimum length of encoded strings to hunt. Default is 5.
  -x MAXLEN, --maxlen MAXLEN
                        The maximum length of encoded strings to hunt. Default is 50.
  -b BASE, --base BASE  The base of encoded strings to hunt. 16, 32 and 64 supported. Default is 64.
```
