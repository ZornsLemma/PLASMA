# TODO: I *think* Python on Windows is installed by default so .py files are
# executed by python but python itself is not on the path. So (not just in this
# file) we should probably make our .py files executable (using /usr/bin/env or
# whatever on Unix) and execute them directly rather than via 'python foo.py'
# for portability.

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
    # TODO!
    return filename + '.a'


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

    imports[module_name] = import_list
    for module in import_list:
        imported_by[module] = module_name

    # If we're using modules (the standard case), we need to assemble the
    # .a file produced by compile_pla() into a .mo.
    if extension == '.a':
        assert not standalone
        full_filename = assemble(full_filename)
        import_list = get_module_imports(full_filename)

    module_filename[module_name] = full_filename


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
        if 'CMDSYS' in ordered_modules_set:
            all_modules_set.add('CMDSYS')
        missing_modules = ordered_modules_set - all_modules_set
        irrelevant_modules = all_modules_set - ordered_modules_set
        # We can't have any "irrelevant" modules; any such module would be a
        # top-level module and therefore will be in ordered_modules_set.
        assert not irrelevant_modules

        if missing_modules:
            # TODO: Optionally allow automatic location of these from library directories
            if False:
                missing_modules_copy = missing_modules.copy()
                for module in missing_modules_copy:
                    if we_found_it:
                        missing_modules.remove(module)
                        add_file('the/filename/of/version/found/in/library')
                        files_added = True
                if files_added:
                    continue
            die("Missing dependencies: " + ', '.join(missing_modules))



# TODO: Use the argument groups feature for nicer --help output
# TODO: Way more arguments than this of course
parser = argparse.ArgumentParser(description='TODO.')
parser.add_argument('inputs', metavar='FILE', nargs='+', help='an input file')
args = parser.parse_args()

standalone = False
ssd = True
bootable = False

imports = {}
imported_by = {}
module_init_line = {}
module_filename = {}

for filename in args.inputs:
    add_file(filename)

# SSDs of modules and standalone executables (whether put on an SSD or not)
# trigger dependency checking, as we need (especially for the standalone
# executable case) a complete set of modules to be available.
if ssd or standalone:
    check_dependencies()

print 'module_init_line:', module_init_line
print 'module_filename:', module_filename

print 1/0
        

# TODO: MORE - WE'RE DONE IF WE'RE NOT GENERATING STANDALONE OR SSD, STANDALONE NEEDS ALL THE STUFF IN PC.PY, SSD MAY BE STANDALONE OR NOT REMEMBER BUT IT'S A QUESTION OF PUTTING THE STANDALONE EXECUTABLE OR ALL THE .MO FILES FOR NON-STANDALONE ONTO SSD

# TODO: WHEN WRITING AN SSD FULL OF MODULES, WE SHOULD ADD THE FILES IN
# 'REVERSE' ORDER OF ordered_modules (AND ACTUALLY WE SHOULD TAKE STEPS TO
# PRESERVE THE RELATIVE ORDER OF INCLUDES WITHIN A GIVEN MODULE), IN THE HOPE
# THAT ON A PHYSICAL FLOPPY THIS WILL MEAN THE DRIVE HEAD WILL NATURALLY SEEK
# 'FORWARDS' THROUGH THE MODULES AS THE VM LOADS THEM. (IF IT IS BOOTABLE, IT
# SHOULD START WITH !BOOT THEN PLASMA &/OR PLAS128 EXECUTABLE, THEN THE
# MODULES.)
