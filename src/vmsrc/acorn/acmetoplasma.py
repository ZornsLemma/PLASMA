from __future__ import print_function

import argparse
import sys

def die(s):
    sys.stderr.write(s + '\n')
    sys.exit(1)

parser = argparse.ArgumentParser(description=
        'Convert ACME constant definitions to PLASMA.')
parser.add_argument('input', metavar='INPUT', type=argparse.FileType('r'), help="input file (simple ACME source file)")

args = parser.parse_args()

print("// AUTOGENERATED; DO NOT EDIT THIS FILE - edit plvmzp.inc instead\n")

for line in args.input:
    line = line[:-1]
    i = line.find(";")
    if i == -1:
        code = line
        comment = ""
    else:
        code = line[:i]
        comment = line[i:].replace(";", "//", 1)
    if code.strip() != "":
        if code.find("=") == -1:
            die("Unable to convert line: " + line)
        code = "const " + code.lower()
    print(code + comment)
