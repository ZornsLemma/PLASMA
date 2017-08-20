# TODO: Check final version for any hard-coded '/' Unix-style path separators -
# we should be using os.path.join() etc

# TODO: I *think* Python on Windows is installed by default so .py files are
# executed by python but python itself is not on the path. So (not just in this
# file) we should probably make our .py files executable (using /usr/bin/env or
# whatever on Unix) and execute them directly rather than via 'python foo.py'
# for portability.

# TODO: This should have a verbose output mode which shows commands it's
# executing, deductions it is making about module dependencies etc

# TODO: In order to allow use of this in separate directories, we will probably
# need to do something about include (both PLASMA and ACME in embedded
# assembler, for e.g. the plvmzp.inc or whatever file) files - I suspect we
# would need to recognise these in the source, attempt to locate them using our
# own -I-specified include paths a la gcc and rewrite them in the source to use
# absolute paths so PLASMA/ACME can find them. We might also need some care to
# interpret relative paths carefully, if we are compiling a .pla file from a
# library it may not be obvious where relative paths should be interpreted from
# (the "standard" PLASMA source is in samplesrc or lib directories, but it is
# designed to be compiled from the parent directory of those, not those
# directories itself - but maybe this is a non-issue if we fix up includes,
# probably have to suck it and see)

import argparse
import ast
import atexit
import collections
import os
import re
import subprocess
import sys
import tempfile

# TODO: THIS COMMENT IS OUTDATED BUT LET'S KEEP IT FOR NOW - WAS ONLY A TEMP NOTE ANYWAY
# single .pla -> .mo/#FExxxx file
# single .pla -> SSD with .mo plus any additional .mo required plus VM executable
# multiple .pla -> executable
# multiple .pla -> SSD containing executable
# SSDs may be optionally bootable and will boot "the main module/executable"

# TODO: This is currently written so all intermediate files are persistent. Might 
# be nice to have an option to use temporary files instead - we'd shove them in a big list
# and remove them on exit, and I guess we could simply have the temporary code disable itself
# when generating a file with an extension which is "the ultimate target" for the build (e.g.
# .ssd for SSD builds, .mo for non-SSD module builds, .a/.sa for -S builds, etc)


def warn(s):
    sys.stderr.write(s + '\n')

def die(s):
    sys.stderr.write(s + '\n')
    sys.exit(1)

def verbose(level, s):
    if args.verbose >= level:
        sys.stderr.write(s + '\n')

def verbose_subprocess(args):
    # TODO: This won't emit properly escaped shell commands; it's probably good
    # enough though - especially since this script is intended to be portable
    # and the escaping conventions are OS-dependent.
    print 'XXX', args
    verbose(1, ' '.join(args))


def cat(o, i):
    with open(i, 'r') as f:
        for line in f:
            o.write(line)


tempfiles = []
def remove_tempfiles():
    for f in tempfiles:
        verbose(1, 'Removing file ' + f)
        os.remove(f)


# TODO: Use this everywhere appropriate
def get_output_name(filename, extension):
    if args.save_temps or extension == target_extension:
        print 'XXXQ2', filename, extension
        return filename + extension
    else:
        f = tempfile.NamedTemporaryFile(mode='w', suffix=extension, delete=False)
        f.close()
        print 'XXXQ1', f.name
        tempfiles.append(f.name)
        return f.name



# TODO: Not good that this uses 'imports' as a local variable when we have a global called that, it's confusing
def compile_pla(full_filename):
    filename, extension = os.path.splitext(full_filename)
    prefix = '_' + os.path.basename(filename).upper() + '_'
    plasm_args = ['./plasm', '-A'] # TODO: Allow user to add to this
    if not args.standalone:
        plasm_args.append('-M')
    if args.optimise:
        plasma_args.append('-O')
    if args.no_combine:
        plasma_args.append('-N')
    if args.warn:
        plasma_args.append('-W')
    imports = []
    init_line = None
    output_extension = '.sa' if args.standalone else '.a'
    output_name = get_output_name(filename, output_extension)
    verbose_subprocess(plasm_args + ['< ' + full_filename, ('| standalone-filter ' if args.standalone else '') + '> ' + output_name])
    plasm = subprocess.Popen(plasm_args, stdin=open(full_filename, 'r'), stdout=subprocess.PIPE)
    with open(output_name, 'w') as output:
        for line in plasm.stdout:
            if args.standalone:
                # TODO: We could strip the leading JMP _INIT off the plasm output - it's redundant
                if line.startswith('_INIT'):
                    # TODO: This is a bit hacky
                    next_line = plasm.stdout.next()
                    if 'JSR' in next_line and 'INTERP' in next_line:
                        line = '_INIT' + prefix
                        init_line = line
                        output.write(line + '\n')
                        line = next_line
                    else:
                        line = None
                elif line.startswith('\t; IMPORT: '):
                    imported_module = line.split(':')[1].strip()
                    if imported_module != 'CMDSYS':
                        imports.append(imported_module)
                else:
                    line = re.sub(r'\b_([ABCDFPX])', prefix + r'\1', line)
                    # These three functions are in cmdsys.plh so they are imported by just
                    # about every program, but they make no sense in a standalone build. We
                    # comment out the imports so any use of them will fail at assembly time.
                    # This seems better than wasting memory on a dummy implementation (albeit
                    # they can probably all just be a single assembly function which does
                    # nothing but RTS).
                    if '= _Y_MODADDR' in line or '= _Y_MODLOAD' in line or '= _Y_MODEXEC' in line:
                        line = '; ' + line
            if line is not None:
                output.write(line)

    # imports will be empty for module builds; we determine them later on.
    return output_name, imports, init_line


def assemble(asm_filename, output_filename):
    # TODO: We need to allow various args to be passed to acme
    # TODO!
    acme_args = ['acme']
    if args.standalone:
        acme_args.extend(['-DSTART=$' + format(load_address, 'x')])
    else:
        acme_args.extend(['--setpc', '4094'])
    if args.defines:
        for define in args.defines:
            acme_args.append('-D' + define[0])
    acme_args += ['-o', output_filename, asm_filename]
    verbose_subprocess(acme_args)
    acme_result = subprocess.call(acme_args)
    if acme_result != 0:
        sys.exit(acme_result)
    return output_filename


def get_module_imports(full_filename):
    with open(full_filename, 'rb') as f:
        # We only read 128 bytes as that's all the PLASMA VM does; it probably
        # wouldn't hurt to read the whole file but this might improve
        # performance slightly.
        # TODO: We could also perhaps validate the entire module header fits
        # within 128 bytes and die if not; this is not directly related to this
        # script's function, but it would make the problem visible before
        # mysterious load-time errors occur on the 8-bit machine.
        data_tmp = f.read(128)
        data = []
        for d in data_tmp:
            data.append(ord(d))

    def byterel(i):
        return data[i]
    def wordrel(i):
        return data[i] + (data[i+1]<<8)
    def dcistrrel(i):
        s = ""
        length = 0
        while byterel(i) & 0x80:
            s += chr(byterel(i) & ~0x80)
            i += 1
        s += chr(byterel(i))
        return s

    if wordrel(2) != 0xda7e+1:
        die("Unrecognised module format: " + full_filename)

    import_list = []
    moddep = 12
    while byterel(moddep):
        s = dcistrrel(moddep)
        moddep += len(s)
        if s != "CMDSYS":
            import_list.append(s)
    return import_list


def add_file(full_filename):
    filename, extension = os.path.splitext(full_filename)
    module_name = os.path.basename(filename).upper()
    if module_name in imports.keys():
        die("Duplicate module name: " + module_name)

    extension = extension.lower()
    if extension == '.pla': # PLASMA source file
        asm_filename, import_list, init_line = compile_pla(full_filename)
        filename, extension = os.path.splitext(full_filename)
        extension = extension.lower()
        module_init_line[module_name] = init_line
        if args.standalone:
            full_filename = asm_filename
        else:
            mo_filename = get_output_name(filename, '.mo')
            full_filename = assemble(asm_filename, mo_filename)
            import_list = get_module_imports(full_filename)
        
    # TODO: we should allow #FEnnnn as well as .mo
    elif extension == '.mo': # pre-compiled module
        if args.standalone:
            die("Standalone build cannot use pre-compiled modules: " + full_filename)
        import_list = get_module_imports(full_filename)
    else:
        die("Invalid input: " + full_filename)

    module_filename[module_name] = full_filename
    imports[module_name] = import_list
    verbose(1, "Module " + module_name + " imports: " + ", ".join(import_list))
    for module in import_list:
        imported_by[module] = module_name


def find_module_by_name(module_name):
    # TODO: Path needs to be configurable and have sensible default (probably
    # based on location of plasmac.py)
    search_path = ['/home/steven/src/PLASMA/src/libsrc', '/home/steven/src/PLASMA/src/samplesrc']
    candidates = []
    acceptable_extensions = ['.pla']
    if not args.standalone:
        acceptable_extensions.append('.mo')
    for path in search_path:
        for extension in acceptable_extensions:
            filename = os.path.join(path, module_name.lower() + extension)
            print 'YYY', filename
            if os.path.exists(filename):
                candidates.append(filename)
    print 'XXX', candidates
    newest_candidate = None
    newest_candidate_mtime = None
    for candidate in candidates:
        candidate_mtime = os.path.getmtime(candidate)
        if newest_candidate_mtime is None or newest_candidate_mtime < candidate_mtime:
            newest_candidate = candidate
            newest_candidate_mtime = candidate_mtime
    print 'ZZZ', newest_candidate
    return newest_candidate


def check_dependencies():
    top_level_modules = [m for m in imports.keys() if m not in imported_by.keys()]
    print 'TLM', top_level_modules

    # If we're building a standalone executable, we must have exactly one top-level module,
    # i.e. a module which isn't imported by any other module, and we also need all the
    # modules imported by that module, etc. This applies whether or not we're building an SSD.
    #
    # If we're building an SSD of modules, we can have multiple top-level modules
    # (the user will decide what to run at the PLASMA prompt) but we need to have
    # all the modules imported by those modules, etc. If the SSD is also bootable, we
    # must have a single top-level module so we know what to boot. TODO: That restriction
    # is perhaps excessive, we could default to the first top-level module or allow the
    # user to specify it explicitly. One module could explicitly load other modules - 
    # a relationship not present in the import information - and thus play the role of
    # the true top-level module, but we'd refuse to build such an SSD at present.
    #
    # If we're building modules without putting them on an SSD, we don't have to worry
    # about dependencies as we have no idea what context the module will be used in.

    if args.standalone and len(top_level_modules) == 0:
        die("Standalone build requires a top-level module")
    if (args.standalone or (args.ssd and args.bootable)) and len(top_level_modules) > 1:
        if args.standalone:
            s = "Standalone build"
        else:
            s = "Bootable module SSD"
        die(s + " requires a single top-level module; we have: " + ', '.join(top_level_modules))
    if args.standalone and not module_init_line[top_level_modules[0]]:
        die("Top-level module " + top_level_modules[0] + " has no initialisation code")

    def recursive_imports(module, imports, seen):
        print 'X923', module, seen
        assert module not in seen
        seen.add(module)
        result = []
        if module in imports: # if it's not, we'll notice later TODO CHECK
            for imported_module in imports[module]:
                if imported_module not in seen:
                    result.extend(recursive_imports(imported_module, imports, seen))
        result.append(module)
        return result

    files_added = True
    while files_added:
        files_added = False

        ordered_modules = []
        seen = set()
        for module in top_level_modules:
            ordered_modules.extend(recursive_imports(module, imports, seen))
        # ordered_modules contains the top-level modules and all of their imports,
        # direct and indirect, ordered so that the lowest level modules come first -
        # this is the order we want to invoke their initialisation code in a standalone
        # executable. TODO MAKE SURE WE USE IT
        print 'QQNEW', ordered_modules

        ordered_modules_set = set(ordered_modules)
        all_modules_set = set(imports.keys())
        missing_modules = ordered_modules_set - all_modules_set
        irrelevant_modules = all_modules_set - ordered_modules_set
        # We can't have any "irrelevant" modules; any such module would be a
        # top-level module and therefore will be in ordered_modules_set.
        assert not irrelevant_modules

        if missing_modules:
            # TODO: Allow user to specify empty set of search paths to make
            # this behaviour effectively optional
            missing_modules_copy = missing_modules.copy()
            for module in missing_modules_copy:
                module_path = find_module_by_name(module)
                if module_path:
                    missing_modules.remove(module)
                    add_file(module_path)
                    files_added = True
            if files_added:
                continue
            die("Missing dependencies: " + ', '.join(missing_modules))

    return ordered_modules, top_level_modules


# TODO: In general but certainly in this function we are totally inconsistent
# about passing some values in as arguments and using others from global variables
def build_standalone(ordered_modules, top_level_modules):
    assert len(top_level_modules) == 1
    # TODO: This always creates files in current directory; that's probably OK, but
    # do think about this again later.
    combined_asm_filename = get_output_name(top_level_modules[0].lower(), '.ca')
    verbose(1, 'Combining module assembly into ' + combined_asm_filename)
    with open(combined_asm_filename, 'w') as combined_asm_file:
        # TODO: Don't hardcode location of input files
        cat(combined_asm_file, 'vmsrc/plvmbb-pre.s')
        with open('vmsrc/32cmd.sa', 'r') as infile:
            for line in infile:
                if line.endswith(': done\n'):
                    discard = infile.next()
                    assert discard == '\t!BYTE\t$00\t\t\t; ZERO\n'
                    discard = infile.next()
                    assert discard == '\t!BYTE\t$5C\t\t\t; RET\n'
                combined_asm_file.write(line)
        for module in ordered_modules:
            init = module_init_line[module]
            if init:
                combined_asm_file.write('\t!BYTE\t$54\t\t\t; CALL ' + init + '\n')
                combined_asm_file.write('\t!WORD\t' + init + '\n')
        # TODO: What can/should we do (perhaps nothing) to "cope" if the final init returns? (It shouldn't)
        for module in ordered_modules:
            cat(combined_asm_file, module_filename[module])
        cat(combined_asm_file, 'vmsrc/plvmbb-post.s')

    if args.compile_only:
        sys.exit(0)

    # TODO: This needs to do all the relocatable/non-relocatable stuff - don't forget to pass -DNONRELOCATABLE=1 to acme if appropriate
    executable_filename = get_output_name(top_level_modules[0].lower(), '')
    assemble(combined_asm_filename, executable_filename)
    return executable_filename



# TODO: Use the argument groups feature for nicer --help output
# TODO: Way more arguments than this of course
# TODO: Check we actually implement all these arguments!
parser = argparse.ArgumentParser(description='PLASMA build tool; transforms PLASMA source code (foo.pla) into PLASMA modules (foo.mo) or standalone executables. The output can optionally be written to an Acorn DFS disc image (foo.ssd).')
parser.add_argument('inputs', metavar='FILE', nargs='+', help="input file (.pla or .mo)")
# TODO: Have a "this tool arguments" group???
parser.add_argument('-v', '--verbose', action='count', help='show what this tool is doing')
parser.add_argument('-S', '--compile-only', action='store_true', help="stop after compiling; don't assemble compiler output")
parser.add_argument('-L', '--library', nargs=1, metavar='DIR', action='append', help="search DIR for missing imports")
parser.add_argument('--save-temps', action='store_true', help="don't remove temporary files")

compiler_group = parser.add_argument_group('compiler arguments', 'Options passed through to the PLASMA compiler (plasm)')
# -A is pointless but we accept it for compatibility with plasm
compiler_group.add_argument('-A', '--acme', action='store_true', help='generate ACME-compatible output (default)')
compiler_group.add_argument('-O', '--optimise', action='store_true', help='enable optimiser')
compiler_group.add_argument('-N', '--no-combine', action='store_true', help='prevent optimiser combining adjacent opcode sequences')
compiler_group.add_argument('-W', '--warn', action='store_true', help='enable warnings')

assembler_group = parser.add_argument_group('assembler arguments', 'Options controlling the assembler (ACME)')
# We don't allow the report name to be specified, partly because it's awkward with argparse
# but mainly because it avoids problems when we're compiling multiple files to modules.
# TODO: Not saying I want to get rid of it, but I suspect --report is going to be a bit awkward with --save-temps. We probably want to make target_extensions a list so we can add '.lst' to it, but we are likely to end up generating '/tmp/dfasdasda.lst' files because the temporary filenames we are working with will naively be used as a base for the .lst name. We may need to pass the "conceptual" filename around with the actual filename all the time or something like that. Maybe we could create all our temp files in a directory and ensure they have the correct leafname? But that sounds awkward and error prone and I don't really like it.
assembler_group.add_argument('-r', '--report', action='store_true', help='generate a report file')
assembler_group.add_argument('-D', metavar='SYMBOL=VALUE', nargs=1, action='append', dest='defines', help='define global symbol')

standalone_group = parser.add_argument_group('standalone executable generator arguments', 'Options controlling generation of a standalone executable (instead of PLASMA modules)')
# The -M argument is really redundant but we allow it for "compatibility" with invoking plasm directly
standalone_group.add_argument('-M', '--module', action='store_true', help='generate a PLASMA module (default)')
standalone_group.add_argument('--standalone', action='store_true', help='generate a standalone executable')
standalone_group.add_argument('--non-relocatable', action='store_true', help="don't include self-relocation code (implies --standalone)")
standalone_group.add_argument('--load-address', nargs=1, metavar='ADDR', help="set executable load address (implies --standalone)")

ssd_group = parser.add_argument_group('ssd generator arguments', 'Options controlling generation of a disc image (instead of host files)')
# TODO: It would be nice if argparse support GNU-style --ssd or --ssd=foo.ssd, but it doesn't;
# using an optional argument with nargs='?' is greedy and it will consume an input file argument.
ssd_group.add_argument('--ssd', action='store_true', help="generate Acorn DFS disc image (.ssd)")
ssd_group.add_argument('--ssd-name', help="output file for --ssd (implies --ssd)")
ssd_group.add_argument('--bootable', action='store_true', help='make disc image bootable (implies --ssd)')
ssd_group.add_argument('--title', nargs=1, metavar='TITLE', help='set disc title (implies --ssd)')

args = parser.parse_args()
print 'QPE', args.ssd, args.verbose

if args.no_combine and not args.optimise:
    warn("--no-combine has no effect without --optimise")

if args.non_relocatable or args.load_address:
    args.standalone = True

if args.standalone and args.module:
    die("--standalone and --module are mutually exclusive")

if args.ssd_name or args.bootable or args.title:
    args.ssd = True

if args.compile_only and args.ssd:
    warn("Ignoring --ssd as --compile_only specified")
    args.ssd = False

load_address = ast.literal_eval(args.load_address[0].replace('$', '0x')) if args.load_address else 0x2000
del args.load_address

# Get rid of redundant arguments so we don't accidentally write code to check them
# when we should be checking some other related argument instead.
del args.acme
del args.module

atexit.register(remove_tempfiles)

if args.ssd:
    target_extension = '.ssd'
elif args.standalone:
    if args.compile_only:
        # TODO: Not very happy with this extension, but we 'need' to distinguish
        # a merged standalone assembly source file from the individual .sa files
        # built for each module and from '.a' files generated during module builds.
        target_extension = '.ca'
    else:
        target_extension = '' # TODO: Not sure if this will work
else:
    if args.compile_only:
        target_extension = '.a'
    else:
        target_extension = '.mo'
verbose(2, 'Target extension: ' + target_extension)

imports = {}
imported_by = {}
module_init_line = {}
module_filename = {}

for filename in args.inputs:
    add_file(filename)

# If we're just building modules from PLASMA source, there's nothing else to
# do.
if not (args.ssd or args.standalone):
    sys.exit(0)

# SSDs of modules and standalone executables (whether put on an SSD or not)
# trigger dependency checking, as we need (especially for the standalone
# executable case) a complete set of modules to be available.
ordered_modules, top_level_modules = check_dependencies()

print 'module_init_line:', module_init_line
print 'module_filename:', module_filename

if args.standalone:
    executable_filename = build_standalone(ordered_modules, top_level_modules)
    output_files = [(executable_filename, top_level_modules[0].upper()[:7])]
else:
    # We reverse the order of ordered_modules so that the files appear on the
    # disc in the physical order the PLASMA VM will open them; this isn't
    # a huge win as it will still end up seeking backward through dependency
    # chains (the VM will open the file to read the header, then seek forward
    # to read each dependency, then once the dependencies are loaded will
    # seek back to read the body of the file) but we might as well try.
    output_files = [(module_filename[module], module[:7]) for module in ordered_modules[::-1]]

if not args.ssd:
    sys.exit(0)

# TODO: Don't hardcode path
import makedfs
disc = makedfs.Disk()
disc.new()
catalogue = disc.catalogue()
catalogue.boot_option = 3 if args.bootable else 0
disc_files = []

def add_dfs_file(source_filename, content, dfs_filename, load_addr, exec_addr):
    assert not (source_filename and content)
    assert source_filename or content
    if source_filename:
        with open(source_filename, 'rb') as f:
            content = f.read()
    if '.' not in dfs_filename:
        dfs_filename = '$.' + dfs_filename
    verbose(1, "Adding %s to SSD as %s, load address $%05X, exec address $%05X" % (source_filename if source_filename else repr(content), dfs_filename, load_addr, exec_addr))
    disc_files.append(makedfs.File(dfs_filename, content, load_addr, exec_addr, len(content)))

if args.bootable:
    # We could of course use the *RUN boot option and have the standalone
    # executable or the PLASMA VM be !BOOT, but there seems little value in
    # it and it's potentially confusing, so let's not do it unless a real
    # benefit turns up. (I suppose it saves one filename, which just may be
    # useful for a module-based SSD, but even that seems pretty tenuous.)
    if args.standalone:
        content = '*RUN ' + top_level_modules[0][:7] + '\r'
    else:
        # TODO: Need to allow user to specify which VM to boot
        # TODO: This probably won't work with PLAS128 due to the "tube off" code
        content = '*RUN PLASMA\r+' + top_level_modules[0][:7] + '\r'
    add_dfs_file(None, content, '$.!BOOT', 0x0000, 0x0000)

if not args.standalone: # TODO: Make this optional?
    # TODO: Don't hardcode path
    add_dfs_file("BBPLASMA#FF2000", None, "PLASMA", 0x2000, 0x2000)

for full_filename, dfs_filename in output_files:
    filename, extension = os.path.splitext(full_filename)
    # TODO: Check/warn/die if two filenames are same after truncation
    if args.standalone:
        load_addr = exec_addr = load_address
    else:
        load_addr = exec_addr = 0x0000
    add_dfs_file(full_filename, None, dfs_filename, load_addr, exec_addr)

# If we have multiple top-level modules we just use the first one for the
# default title and default SSD name.
disc_title = args.title[0] if args.title is not None else top_level_modules[0][:12]
print repr(disc_title)
catalogue.write(disc_title, disc_files)
disc.file.seek(0, 0)
if not args.ssd_name:
    args.ssd_name = top_level_modules[0].lower() + '.ssd'
verbose(1, "Writing SSD to " + args.ssd_name)
with open(args.ssd_name, 'wb') as ssd_file:
    ssd_file.write(disc.file.read())
