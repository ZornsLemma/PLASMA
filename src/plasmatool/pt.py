from __future__ import print_function

import argparse
import os
import sys

from module import *
from optimiser import *

# SFTODO: I'm using assert where I should probably use something else; where I'm doing
# "assert False" I could perhaps call die().

def die(s):
    sys.stderr.write(s + '\n')
    sys.exit(1)

def verbose(level, s):
    if args.verbose >= level:
        sys.stderr.write(s + '\n')

parser = argparse.ArgumentParser(description='PLASMA module tool; disassembles and optimises compiled PLASMA modules.')
parser.add_argument('-v', '--verbose', action='count', help='show what this tool is doing')
parser.add_argument('-O', '--optimise', action='store_true', help='enable optimiser')
parser.add_argument('-2', '--second-module-name', dest='name', help="name for second module when splitting (defaults to basename of OUTPUT2)")
parser.add_argument('input', metavar='INPUT', type=argparse.FileType('rb'), help="input file (compiled PLASMA module)")
parser.add_argument('output', metavar='OUTPUT', nargs='?', type=argparse.FileType('w'), default=sys.stdout, help="output file (ACME source file), defaults to standard output")
parser.add_argument('output2', metavar='OUTPUT2', nargs='?', type=argparse.FileType('w'), default=None, help="second output file (ACME source file) for module splitting")

args = parser.parse_args()

module = Module.load(args.input)

if args.optimise:
    Optimiser.optimise(module)

if args.output2 is not None:
    if args.name is not None:
        second_module_name = args.name
    else:
        second_module_name = os.path.splitext(os.path.basename(args.output2.name))[0]
    second_module_name = second_module_name.upper()
    verbose(1, "Splitting module; second output module name is %s" % second_module_name)
    # SFTODO: We could validate second_module_name (not too long, no odd characters)

    second_module = module.split(second_module_name)

module.dump(args.output)
if args.output2 is not None:
    second_module.dump(args.output2)
