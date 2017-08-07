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

def call_acme(address, infile, report):
    acme_args = ['acme', '--setpc', address, '-DSTART=' + address]
    if args.non_relocatable:
        acme_args += ['-DNONRELOCATABLE=1']
    if report:
        acme_args += ['--report', args.report[0]]
    acme_args += ['-o', infile, combined_asm_file.name]
    if args.verbose:
        # TODO: The displayed output won't be a valid shell command because there will be no quoting to stop $ being interpreted. This isn't a huge deal, but here (and in other verbose output) it might be nice to try to write valid shell output
        sys.stderr.write(' '.join(acme_args) + '\n')
    acme_result = subprocess.call(acme_args)
    if acme_result != 0:
        sys.exit(acme_result)

# TODO: Use similar technique to 'Edit:' bit at
# https://stackoverflow.com/questions/9234258/in-python-argparse-is-it-possible-to-have-paired-no-something-something-arg
# for: --bootable={yes,no}, default yes, only relevant if generating SSD
# potentially switch --non-relocatable to same scheme
# --vm={32,128,both} for non-standalone to decide which VM binary(s) to include
# on the disc (probably boot 32 if both present and bootable=yes)
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
parser.add_argument('-r', '--report', action='append', help='assembler report file')
# TODO: Should we support a -M flag like plasm? Depends how we extend this to support non-standalone
parser.add_argument('-d', '--ssd', action='store_true', help='output a DFS disc image (.ssd)')
args = parser.parse_args()

if args.output and len(args.output) > 1:
    die("Only one output file can be specified")

if args.report and len(args.report) > 1:
    die("Only one report file can be specified")

if not args.inputs:
    die("No input files specified")

if args.ssd and args.S:
    die("--ssd and -S are not compatible")

# TODO: For now we assume the most "significant" file is the last one
infile_name, infile_extension = os.path.splitext(args.inputs[-1])
if not args.output:
    if args.S:
        args.output = [infile_name + '.a']
    elif args.ssd:
        args.output = [infile_name + '.ssd']
    else:
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

# TODO: Rename outfile variable? We have multiple output files...
if args.S:
    combined_asm_file = open(args.output[0], 'w')
else:
    combined_asm_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
    tempfiles.append(combined_asm_file.name)

if args.verbose:
    sys.stderr.write('Combining plasm output into ' + combined_asm_file.name + '\n')

cat(combined_asm_file, 'vmsrc/plvmbb-pre.s')

# We need to take the contents of 32cmd.sa but strip off the ZERO:RET at the end of its
# _INIT, so we can fall through into calling other initialisation code. TODO: A bit hacky
# the way we recognise this...
with open('vmsrc/32cmd.sa', 'r') as infile:
    for line in infile:
        if line.endswith(': done\n'):
            discard = infile.next()
            assert discard == '\t!BYTE\t$00\t\t\t; ZERO\n'
            discard = infile.next()
            assert discard == '\t!BYTE\t$5C\t\t\t; RET\n'
        combined_asm_file.write(line)

for init in init_list:
    combined_asm_file.write('\t!BYTE\t$54\t\t\t; CALL ' + init + '\n')
    combined_asm_file.write('\t!WORD\t' + init + '\n')
# TODO: What can/should we do (perhaps nothing) to "cope" if the final init returns? (It shouldn't)

modules = set(['CMDSYS'])
for infile in args.inputs:
    infile_name, infile_extension = os.path.splitext(infile)
    infile_extension = infile_extension.lower()
    if infile_extension == '.pla':
        our_imports = imports[infile_name]
        if not our_imports.issubset(modules) and not args.force:
            die('Missing or out-of-order dependencies for ' + infile + ': ' + ', '.join(our_imports - modules))
        combined_asm_file.writelines(plasm_output[infile_name + '.sa'])
        modules.add(os.path.basename(infile_name).upper())
    else:
        # TODO: We need to allow user-written assembler source to be specified
        # on the command line.
        die('Unknown file extension: ' + infile)

cat(combined_asm_file, 'vmsrc/plvmbb-post.s')

combined_asm_file.close()

if args.S:
    sys.exit(0)

if not args.ssd:
    executable_file = open(args.output[0], 'w')
else:
    executable_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
    tempfiles.append(executable_file.name)
    executable_file.close()

# TODO: We need to allow our caller to specify options to pass through to ACME
call_acme('$2000', executable_file.name, args.report)
if not args.non_relocatable:
    output_3000 = tempfile.NamedTemporaryFile(mode='w', delete=False)
    tempfiles.append(output_3000.name)
    output_3000.close()
    call_acme('$3000', output_3000.name, None)
    # TODO: Inline the add-relocations.py code? Or maybe make it a module so we can import it?
    relocation_args = ['python', 'add-relocations.py', executable_file.name, output_3000.name]
    if args.verbose:
        sys.stderr.write(' '.join(relocation_args) + '\n')
    relocation_result = subprocess.call(relocation_args)
    if relocation_result != 0:
        die("Adding relocations failed")

if args.ssd:
    import makedfs
    disc = makedfs.Disk()
    disc.new()
    catalogue = disc.catalogue()
    catalogue.boot_option = 0 # TODO!
    disc_files = []
    with open(executable_file.name, 'rb') as executable:
        data = executable.read()
    executable_name = os.path.basename(infile_name).upper()
    if '.' not in executable_name:
        executable_name = '$.' + executable_name
    disc_files.append(makedfs.File(executable_name, data, 0x2000, 0x2000, len(data)))
    catalogue.write(executable_name[2:], disc_files) # TODO: Allow setting title
    disc.file.seek(0, 0)
    with open(args.output[0], 'wb') as ssd_file:
        ssd_file.write(disc.file.read())
