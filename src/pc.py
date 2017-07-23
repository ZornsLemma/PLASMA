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
import atexit
import os
import re
import subprocess
import sys
import tempfile

def die(s):
    sys.stderr.write(s + '\n')
    sys.exit(1)

def cat(o, i):
    with open(i, 'r') as f:
        for line in f:
            o.write(line)

def remove_file(f):
    if args.verbose:
        sys.stderr.write('Removing file ' + f + '\n')
    os.remove(f)

parser = argparse.ArgumentParser(description='TODO.')
parser.add_argument('inputs', metavar='FILE', nargs='+', help='a PLASMA source file')
parser.add_argument('-v', '--verbose', action='store_true', help='increase output verbosity')
parser.add_argument('-o', '--output', action='append', help='output file')
parser.add_argument('-O', action='store_true', help='enable compiler optimisations')
parser.add_argument('-N', '--no-combine', action='store_true', help='disable sequence combining in compiler optimiser')
parser.add_argument('-W', '--warn', action='store_true', help='enable warnings')
parser.add_argument('-S', action='store_true', help='stop after generating assembler input')
# TODO: Should we support a -M flag like plasm? Depends how we extend this to support non-standalone
args = parser.parse_args()

if args.output and len(args.output) > 1:
    die("Only one output file can be specified")

if not args.inputs:
    die("No input files specified")

if not args.output:
    # TODO: For now we assume the most "significant" file is the last one
    infile_name, infile_extension = os.path.splitext(args.inputs[-1])
    if args.S:
        args.output = [infile_name + '.a']
    else:
        # TODO: We should support generating an SSD (and default to .ssd extension) as well as raw file
        args.output = [infile_name]

init_list = []
plasm_output = {}

for infile in args.inputs:
    infile_name, infile_extension = os.path.splitext(infile)
    infile_extension = infile_extension.lower()

    if infile_extension == '.pla':
        # TODO: We should support the same options as plasm and pass them
        # through...
        plasm_args = ['./plasm', '-A']
        if args.O:
            plasm_args.append('-O')
        if args.no_combine:
            plasm_args.append('-N')
        if args.warn:
            plasm_args.append('-W')
        if args.verbose:
            sys.stderr.write(' '.join(plasm_args) + ' < ' + infile + '\n')
        plasm = subprocess.Popen(plasm_args, stdin=open(infile, 'r'), stdout=subprocess.PIPE)
        # TODO: We could strip the leading JMP _INIT off the plasm output - it's redundant
        o = plasm_output[infile_name + '.sa'] = []
        prefix = '_' + os.path.basename(infile_name).upper() + '_'
        for line in plasm.stdout:
            if line[0:5] == '_INIT':
                # TODO: This is a bit hacky
                next_line = plasm.stdout.next()
                if 'JSR' in next_line and 'INTERP' in next_line:
                    line = '_INIT' + prefix
                    init_list.append(line)
                    o.append(line + '\n')
                    line = next_line
                else:
                    line = None
            else:
                line = re.sub(r'\b_([ABCDFPX])', prefix + r'\1', line)
            if line is not None:
                o.append(line)
    else:
        # TODO: We need to allow user-written assembler source to be specified
        # on the command line.
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

# TODO: Rename outfile? We have multiple output files...
if args.S:
    assert args.output # SFTODO: we probably need to generate a default output name if not specified
    outfile = open(args.output[0], 'w')
else:
    outfile = tempfile.NamedTemporaryFile(mode='w', delete=False)
    atexit.register(remove_file, outfile.name)

if args.verbose:
    sys.stderr.write('Combining plasm output into ' + outfile.name + '\n')

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

for init in init_list:
    outfile.write('\t!BYTE\t$54\t\t\t; CALL ' + init + '\n')
    outfile.write('\t!WORD\t' + init + '\n')
# TODO: What can/should we do (perhaps nothing) to "cope" if the final init returns? (It shouldn't)

for infile in args.inputs:
    infile_name, infile_extension = os.path.splitext(infile)
    infile_extension = infile_extension.lower()
    if infile_extension == '.pla':
        outfile.writelines(plasm_output[infile_name + '.sa'])
    else:
        # TODO: We need to allow user-written assembler source to be specified
        # on the command line.
        die('Unknown file extension: ' + infile)

cat(outfile, 'vmsrc/plvmbb-post.s')

outfile.close()

if args.S:
    sys.exit(0)

# TODO: We should support generating relocatable standalone output by invoking
# ACME twice and appending relocations

# TODO: We need to allow our caller to specify options to pass through to ACME
# TODO: --report needs to be optional
acme_args = ['acme', '--setpc', '$2000', '-DSTART=$2000', '--report', 'hanois.lst', '-o', args.output[0], outfile.name]
if args.verbose:
    # TODO: The displayed output won't be a valid shell command because there will be no quoting to stop $ being interpreted. This isn't a huge deal, but here (and in other verbose output) it might be nice to try to write valid shell output
    sys.stderr.write(' '.join(acme_args) + '\n')
acme_result = subprocess.call(['acme', '--setpc', '$2000', '-DSTART=$2000', '--report', 'hanois.lst', '-o', args.output[0], outfile.name])
sys.exit(acme_result)
