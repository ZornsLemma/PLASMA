# TODO: This may well evolve into a general "driver" but right now it's
# focussed exclusively on building standalone binaries.

import argparse
import atexit
import collections
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

tempfiles = []
def remove_files():
    for f in tempfiles:
        if args.verbose:
            sys.stderr.write('Removing file ' + f + '\n')
        os.remove(f)

def call_acme(address, infile):
    acme_args = ['acme', '--setpc', address, '-DSTART=' + address]
    if args.non_relocatable:
        acme_args += ['-DNONRELOCATABLE=1']
    acme_args += ['--report', 'hanois.lst', '-o', infile, outfile.name]
    if args.verbose:
        # TODO: The displayed output won't be a valid shell command because there will be no quoting to stop $ being interpreted. This isn't a huge deal, but here (and in other verbose output) it might be nice to try to write valid shell output
        sys.stderr.write(' '.join(acme_args) + '\n')
    acme_result = subprocess.call(acme_args)
    if acme_result != 0:
        sys.exit(acme_result)

parser = argparse.ArgumentParser(description='TODO.')
parser.add_argument('inputs', metavar='FILE', nargs='+', help='a PLASMA source file')
parser.add_argument('-v', '--verbose', action='store_true', help='increase output verbosity')
parser.add_argument('-o', '--output', action='append', help='output file')
parser.add_argument('-O', action='store_true', help='enable compiler optimisations')
parser.add_argument('-N', '--no-combine', action='store_true', help='disable sequence combining in compiler optimiser')
parser.add_argument('-W', '--warn', action='store_true', help='enable warnings')
parser.add_argument('-S', action='store_true', help='stop after generating assembler input')
parser.add_argument('-f', '--force', action='store_true', help='proceed even if dependency verification fails')
parser.add_argument('--non-relocatable', action='store_true', help="don't generate a self-relocating executable")
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
imports = collections.defaultdict(set)

for infile in args.inputs:
    infile_name, infile_extension = os.path.splitext(infile)
    infile_extension = infile_extension.lower()

    if infile_extension == '.pla':
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
            if line.startswith('_INIT'):
                # TODO: This is a bit hacky
                next_line = plasm.stdout.next()
                if 'JSR' in next_line and 'INTERP' in next_line:
                    line = '_INIT' + prefix
                    init_list.append(line)
                    o.append(line + '\n')
                    line = next_line
                else:
                    line = None
            elif line.startswith('\t; IMPORT: '):
                imports[infile_name].add(line.split(':')[1].strip())
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

atexit.register(remove_files)

# TODO: Rename outfile? We have multiple output files...
if args.S:
    outfile = open(args.output[0], 'w')
else:
    outfile = tempfile.NamedTemporaryFile(mode='w', delete=False)
    tempfiles.append(outfile.name)

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
            assert discard == '\t!BYTE\t$00\t\t\t; ZERO\n'
            discard = infile.next()
            assert discard == '\t!BYTE\t$5C\t\t\t; RET\n'
        outfile.write(line)

for init in init_list:
    outfile.write('\t!BYTE\t$54\t\t\t; CALL ' + init + '\n')
    outfile.write('\t!WORD\t' + init + '\n')
# TODO: What can/should we do (perhaps nothing) to "cope" if the final init returns? (It shouldn't)

modules = set(['CMDSYS'])
for infile in args.inputs:
    infile_name, infile_extension = os.path.splitext(infile)
    infile_extension = infile_extension.lower()
    if infile_extension == '.pla':
        our_imports = imports[infile_name]
        if not our_imports.issubset(modules) and not args.force:
            die('Missing or out-of-order dependencies for ' + infile + ': ' + ', '.join(our_imports - modules))
        outfile.writelines(plasm_output[infile_name + '.sa'])
        modules.add(os.path.basename(infile_name).upper())
    else:
        # TODO: We need to allow user-written assembler source to be specified
        # on the command line.
        die('Unknown file extension: ' + infile)

cat(outfile, 'vmsrc/plvmbb-post.s')

outfile.close()

if args.S:
    sys.exit(0)

# TODO: We need to allow our caller to specify options to pass through to ACME
# TODO: --report needs to be optional
call_acme('$2000', args.output[0])
if args.non_relocatable:
    sys.exit(0)
output_3000 = tempfile.NamedTemporaryFile(mode='w', delete=False)
output_3000.close()
tempfiles.append(output_3000.name)
call_acme('$3000', output_3000.name)
# TODO: Inline the add-relocations.py code? Or maybe make it a module so we can import it?
relocation_args = ['python', 'add-relocations.py', args.output[0], output_3000.name]
if args.verbose:
    sys.stderr.write(' '.join(relocation_args) + '\n')
relocation_result = subprocess.call(relocation_args)
sys.exit(relocation_result)
