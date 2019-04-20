from __future__ import print_function

import argparse
import collections
import os
import sys

from optimiser import Optimiser
from bytecode import *

# This is a pretty large file and ideally some of the classes would be independent modules
# instead. However, since this is just a small utility within the PLASMA distribution I
# want to avoid splitting it across multiple files.

# TODO: I'm using assert where I should probably use something else

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
    # TODO: We could validate second_module_name (not too long, no odd characters)

    second_module = module.split(second_module_name)

module.dump(args.output)
if args.output2 is not None:
    second_module.dump(args.output2)

# TODO: Would it be worth replacing "CN 1:SHL" with "DUP:ADD"? This occurs in the self-hosted compiler at least once. It's the same length, so would need to cycle count to see if it's faster.

# TODO: Perhaps not worth it, and this is a space-not-speed optimisation, but if it's common to CALL a function FOO and then immediately do a DROP afterwards (across all code in the module, not just one function), it may be a space-saving win to generate a function FOO-PRIME which does "(no ENTER):CALL FOO:DROP:RET" and replace CALL FOO:DROP with CALL FOO-PRIME. We could potentially generalise this (we couldn't do it over multiple passes) to recognising the longest common sequence of operations occurring after all CALLs to FOO and factoring them all into FOO-PRIME.

# TODO: Just possibly we should expand DUP if the preceding instruction is a simple_stack_push
# early in the optimisation to make the effects more obvious, and have a final DUP-ification pass which will revert this change where there is still value in the DUP - this might enable other optimisations in the meantime - but it may also make things worse

# TODO: On a B/B+ in non-shadow mode 7 with DFS and ADFS installed, PLAS128 has approximately $415A bytes of main RAM free - so "smaller than this" is the goal for the individual split modules of the compiler, in order to allow them to be loaded into main RAM (before being split up and relocation data discarded and bytecode moved into sideways RAM).

# TODO: Currently splitting the self-hosted compiler with no optimisation fails

# TODO: The peephole optimiser can do things like "LLW [n]:SLW [m]:LLW [n] -> LLW [n]:DLW
# [m]", but we could also do things like "LLW [n]:DLW [m]:SLW [o]:LLW [n] -> LLW
# [m]:DLW [m]:DLW [o]". An arbitrary number of dup-stores after the first LLW would be
# acceptable, not just one; the current peephole optimiser will not do anything if there
# are any dup-stores after the first load instruction.
