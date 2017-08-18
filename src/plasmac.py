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
import collections
import os
import subprocess
import sys

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


# TODO: Not good that this uses 'imports' as a local variable when we have a global called that, it's confusing
def compile_pla(full_filename):
    filename, extension = os.path.splitext(full_filename)
    prefix = '_' + os.path.basename(filename).upper() + '_'
    plasm_args = ['./plasm', '-A'] # TODO: Allow user to add to this
    if not standalone:
        plasm_args.append('-M')
    if args.optimise:
        plasma_args.append('-O')
    if args.no_combine:
        plasma_args.append('-N')
    if args.warn:
        plasma_args.append('-W')
    imports = []
    init_line = None
    plasm = subprocess.Popen(plasm_args, stdin=open(full_filename, 'r'), stdout=subprocess.PIPE)
    if standalone:
        output_name = filename + '.sa'
    else:
        output_name = filename + '.a'
    with open(output_name, 'w') as output:
        for line in plasm.stdout:
            if standalone:
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
                    imports.add(line.split(':')[1].strip())
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


def assemble(full_filename):
    filename, extension = os.path.splitext(full_filename)
    output_name = filename + '.mo'
    # TODO: We need to allow various args to be passed to acme
    # TODO!
    acme_args = ['acme']
    if standalone:
        address = '$2000'
        acme_args.extend(['--setpc', address, '-DSTART=' + address])
    else:
        acme_args.extend(['--setpc', '4094'])
    acme_args += ['-o', output_name, full_filename]
    acme_result = subprocess.call(acme_args)
    if acme_result != 0:
        sys.exit(acme_result)
    return output_name


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
        print compile_pla(full_filename)
        full_filename, import_list, init_line = compile_pla(full_filename)
        filename, extension = os.path.splitext(full_filename)
        extension = extension.lower()
        module_init_line[module_name] = init_line
    # TODO: we should allow #FEnnnn as well as .mo
    elif extension == '.mo': # pre-compiled module
        if standalone:
            die("Standalone build cannot use pre-compiled modules: " + full_filename)
        import_list = get_module_imports(full_filename)
    else:
        die("Invalid input: " + full_filename)

    # If we're using modules (the standard case), we need to assemble the
    # .a file produced by compile_pla() into a .mo.
    if extension == '.a':
        assert not standalone
        full_filename = assemble(full_filename)
        import_list = get_module_imports(full_filename)

    module_filename[module_name] = full_filename
    imports[module_name] = import_list
    print "IMPORTS", module_name, import_list
    for module in import_list:
        imported_by[module] = module_name


def find_module_by_name(module_name):
    # TODO: Path needs to be configurable and have sensible default (probably
    # based on location of plasmac.py)
    search_path = ['/home/steven/src/PLASMA/src/libsrc', '/home/steven/src/PLASMA/src/samplesrc']
    candidates = []
    for path in search_path:
        for extension in ['.mo', '.pla']:
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

    if standalone and len(top_level_modules) == 0:
        die("Standalone build requires a top-level module")
    if (standalone or (ssd and bootable)) and len(top_level_modules) > 1:
        if standalone:
            s = "Standalone build"
        else:
            s = "Bootable module SSD"
        die(s + " requires a single top-level module; we have: " + ', '.join(top_level_modules))
    if standalone and not init_lines[top_level_modules[0]]:
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

        return ordered_modules



# TODO: Use the argument groups feature for nicer --help output
# TODO: Way more arguments than this of course
parser = argparse.ArgumentParser(description='PLASMA build tool; transforms PLASMA source code (foo.pla) into PLASMA modules (foo.mo) or standalone executables. The output can optionally be written to an Acorn DFS disc image (foo.ssd).')
parser.add_argument('inputs', metavar='FILE', nargs='+', help="input file (.pla or .mo)")
# TODO: Have a "this tool arguments" group???
parser.add_argument('-v', '--verbose', action='count', help='show what this tool is doing')
parser.add_argument('-S', '--compile-only', action='store_true', help="stop after compiling; don't assemble compiler output")

compiler_group = parser.add_argument_group('compiler arguments', 'Options passed through to the PLASMA compiler (plasm)')
compiler_group.add_argument('-O', '--optimise', action='store_true', help='enable optimiser')
compiler_group.add_argument('-N', '--no-combine', action='store_true', help='prevent optimiser combining adjacent opcode sequences')
compiler_group.add_argument('-W', '--warn', action='store_true', help='enable warnings')

standalone_group = parser.add_argument_group('standalone generator arguments', 'Options controlling generation of a standalone executable (instead of PLASMA modules)')
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

args = parser.parse_args()
print 'QPE', args.ssd, args.verbose

if args.no_combine and not args.optimise:
    warn("--no-combine has no effect without --optimise")

if args.non_relocatable or args.load_address:
    args.standalone = True

if args.standalone and args.module:
    die("--standalone and --module are mutually exclusive")

if args.ssd_name:
    args.ssd = True

standalone = False
ssd = True
bootable = False

imports = {}
imported_by = {}
module_init_line = {}
module_filename = {}

for filename in args.inputs:
    add_file(filename)

# If we're just building modules from PLASMA source, there's nothing else to
# do.
if not (ssd or standalone):
    sys.exit(0)

# SSDs of modules and standalone executables (whether put on an SSD or not)
# trigger dependency checking, as we need (especially for the standalone
# executable case) a complete set of modules to be available.
ordered_modules = check_dependencies()

print 'module_init_line:', module_init_line
print 'module_filename:', module_filename

if standalone:
    executable_filename = build_standalone(ordered_modules)
    output_files = [executable_filename]
else:
    # We reverse the order of ordered_modules so that the files appear on the
    # disc in the physical order the PLASMA VM will open them; this isn't
    # a huge win as it will still end up seeking backward through dependency
    # chains (the VM will open the file to read the header, then seek forward
    # to read each dependency, then once the dependencies are loaded will
    # seek back to read the body of the file) but we might as well try.
    output_files = [module_filename[module] for module in ordered_modules[::-1]]

if not ssd:
    sys.exit(0)

# TODO: Don't hardcode path
import makedfs
disc = makedfs.Disk()
disc.new()
catalogue = disc.catalogue()
catalogue.boot_option = 0 # TODO!
disc_files = []

def add_dfs_file(source_filename, content, dfs_filename, load_addr, exec_addr):
    assert not (source_filename and content)
    assert source_filename or content
    if source_filename:
        with open(source_filename, 'rb') as f:
            content = f.read()
    if '.' not in dfs_filename:
        dfs_filename = '$.' + dfs_filename
    disc_files.append(makedfs.File(dfs_filename, content, load_addr, exec_addr, len(content)))

if bootable:
    # TODO: Add a !BOOT file
    pass

if not standalone: # TODO: Make this optional?
    # TODO: Don't hardcode path
    add_dfs_file("BBPLASMA#FF2000", None, "PLASMA", 0x2000, 0x2000)

for full_filename in output_files:
    if standalone:
        load_addr = exec_addr = 0x2000
    else:
        load_addr = exec_addr = 0x0000
    filename, extension = os.path.splitext(full_filename)
    # TODO: Check/warn/die if two filenames are same after truncation
    dfs_filename = os.path.basename(filename)[:7].upper()
    add_dfs_file(full_filename, None, dfs_filename, load_addr, exec_addr)


catalogue.write("TITLE", disc_files) # TODO: Allow setting title and provide sensible default
disc.file.seek(0, 0)
# TODO: Allow command line to specify SSD filename and have a sensible default
with open('foo.ssd', 'wb') as ssd_file:
    ssd_file.write(disc.file.read())
