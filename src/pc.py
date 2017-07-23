# TODO: This may well evolve into a general "driver" but right now it's
# focussed exclusively on building standalone binaries.

# It seems to be the convention that "normal" assembly output from 'plasm -AM'
# intended to be assembled into a module has a '.a' extension. We therefore use
# a '.sa' extension to distinguish (incompatible) standalone assembly output.

# TODO: We could (eventually) "expect" a correlation between input filenames
# and module names, and topologically sort the inputs to ensure "correct"
# ordering - with an option to override this and use the order provided with no
# assumptions about that correlation. As a halfway step, we could not check the
# order but check (unless overridden) that every dependency has a corresponding
# input file (i.e. check we have the expected set of files, but not check the
# order).

import argparse
import os
import re
import subprocess
import sys

def die(s):
    sys.stderr.write(s + '\n')
    sys.exit(1)

def cat(o, i):
    with open(i, 'r') as f:
        for line in f:
            o.write(line)

parser = argparse.ArgumentParser(description='TODO.')
parser.add_argument('inputs', metavar='FILE', nargs='+', help='a PLASMA source file')
args = parser.parse_args()

init_list = []
assembler_input = []

for infile in args.inputs:
    infile_name, infile_extension = os.path.splitext(infile)
    infile_extension = infile_extension.lower()

    if infile_extension == '.pla':
        # TODO: We should support the same options as plasm and pass them
        # through...
        plasm = subprocess.Popen(['./plasm', '-A'], stdin=open(infile, 'r'), stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
        # TODO: We could strip the leading JMP _INIT off the plasm output - it's redundant
        with open(infile_name + '.sa', 'w') as outfile:
            prefix = '_' + os.path.basename(infile_name).upper() + '_'
            for line in plasm.stdout:
                if line[0:5] == '_INIT':
                    # TODO: This is a bit hacky
                    next_line = plasm.stdout.next()
                    if 'JSR' in next_line and 'INTERP' in next_line:
                        line = '_INIT' + prefix
                        init_list.append(line)
                        outfile.write(line + '\n')
                        line = next_line
                    else:
                        line = None
                else:
                    line = re.sub(r'\b_([ABCDFPX])', prefix + r'\1', line)
                if line is not None:
                    outfile.write(line)
        infile_extension = '.sa'

    if infile_extension == '.sa':
        # TODO: We need to populate init_list - we get away with it if we just did the previous step
        assembler_input.append(infile_name + infile_extension)
    else:
        die('Unknown file extension: ' + infile)

if not init_list:
    # TODO: Eventually this should fail if the "main" program - however we decide to indicate
    # that - has no INIT, even if other modules do.
    die("No initialisation code to call!")

# TODO: We should probably not actually be generating a single output file here
# - I was thinking we should invoke 'acme' ourselves (I only hadn't got round
# to that yet) and give it multiple files on the command line. We could do the
# hackery on 32cmd.sa when we generate it as part of the "tool build". However,
# would we have trouble generating the series of calls to _INIT_XXX? Well, not
# trouble as such, but if we generated this as a "permanent" file, what name
# would it have? Would we just shove it in a temporary file and discard it
# afterwards? That's not ideal for debugging build problems where we'd like to
# invoke acme manually. Maybe it would be best if we did the concatenation to a
# single file, by default a temp file, but with a -S option to say "generate
# the concatenated file and don't assemble it" for debugging - we could include
# comments delimiting the various files which went into it. Let's not forget
# that performance isn't really an issue - the extra time and disc space
# required for the concatenated file creation is negligible.
output_asm = 'foo' # SFTODO: need to decide what path/name to use for this
with open(output_asm, 'w') as outfile:
    cat(outfile, 'vmsrc/plvmbb-pre.s')

    # We need to take the contents of 32cmd.sa but strip off the ZERO:RET at the end of its
    # _INIT, so we can fall through into calling other initialisation code. TODO: A bit hacky
    # the way we recognise this...
    with open('vmsrc/32cmd.sa', 'r') as infile:
        for line in infile:
            distinctive = ': done\n'
            if line[-len(distinctive):] == distinctive:
                discard = infile.next()
                discard = infile.next()
            outfile.write(line)

    # TODO: We don't want this, I think - 32cmd.sa has already started interpreting and we're appending to the end of its bytecode init  outfile.write('\tJSR\tINTERP\n')
    for init in init_list:
        outfile.write('\t!BYTE\t$54\t\t\t; CALL ' + init + '\n')
        outfile.write('\t!WORD\t' + init + '\n')
    # TODO: What can/should we do (perhaps nothing) to "cope" if the final init returns? (It shouldn't)

    for asm in assembler_input:
        cat(outfile, asm)

    cat(outfile, 'vmsrc/plvmbb-post.s')

