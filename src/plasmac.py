import argparse
import collections
import os
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

def compile_pla(source):
    # TODO: Invokes plasm with appropriate options, returning filename of plasm
    # output - the returned filename will have a .a or .sa extension depending
    # on whether we're doing standalone build or not
    if 'LIB' not in source:
        return source + '.a', ['LIB1', 'LIB2'], ''
    else:
        return source + '.a', [], ''
    assert False

# TODO: Use the argument groups feature for nicer --help output
# TODO: Way more arguments than this of course
parser = argparse.ArgumentParser(description='TODO.')
parser.add_argument('inputs', metavar='FILE', nargs='+', help='an input file')
args = parser.parse_args()

files = args.inputs
standalone = False
ssd = False
bootable = False

imports = [None] * len(files)
init = [None] * len(files)
module_names = [None] * len(files)
dependencies = [None] * len(files)

files_added = True
while files_added:
    files_added = False

    for i in range(len(files)):
        filename, extension = os.path.splitext(files[i])

        module_name = os.path.basename(filename).upper()
        if module_name in module_names:
            die("Duplicate module name: " + module_name)
        module_names[i] = module_name

        extension = extension.lower()
        if extension == '.pla': # PLASMA source file
            print compile_pla(files[i])
            files[i], imports[i], init[i] = compile_pla(files[i])
        # TODO: we should allow #FEnnnn as well as .mo
        elif extension == '.mo': # pre-compiled module
            if standalone:
                die("Invalid input for standalone build: " + files[i])
            imports[i] = get_module_imports(files[i])
        else:
            die("Invalid input: " + files[i])

        # If we're using modules (the standard case), we need to assemble the
        # .a file produced by compile_pla() into a .mo.
        if extension == '.a':
            files[i] = assemble(files[i])

    root_modules = []
    dependency_tree = collections.defaultdict(list)
    for i in range(len(files)):
        print i
        print files[i]
        print 'X', imports[i], 'X'
        print 'Y', init[i], 'Y'
        print
        for imported_module in imports[i]:
            dependency_tree[imported_module].append(module_names[i])
    top_level_modules = [module for module in module_names if module not in dependency_tree.keys()]
    print top_level_modules

    if standalone and len(top_level_modules) == 0:
        die("Standalone build requires a top-level module")
    if (standalone or (ssd and bootable)) and len(top_level_modules) > 1:
        if standalone:
            s = "Standalone build"
        else:
            s = "Bootable SSD"
        die(s + " requires a single top-level module; we have: " + ', '.join(top_level_modules))
    if standalone and top_level_modules[0] does_not_have_an_init:
        die("Top-level module " + top_level_modules[0] + " has no initialisation code")

    if standalone or ssd:
        modules_seen = ['CMDSYS'] # TODO WE ARE NEVER USING THIS
        modules_todo = top_level_modules
        while len(modules_todo) > 0:
            modules_seen.append[modules_todo[0]]
            imports = TODOIMPORTSFORmodules_todo[0]
            modules_todo = modules_todo[1:]
            for imported_module in imports:
                if imported_module not in module_names: # TODO: CMDSYS NOT IN module_names BUT IT IS OK
                    # TODO: Locate it from a library and trigger reprocessing
                    die("Imported module " + imported_module + " missing")
                modules_todo.append(imported_module)
        if standalone and (anything is in module_names but not modules_todo):
            warn("Ignoring unreferenced modules: TODOLIST")

    # TODO: ROUGHLY SPEAKING WE WANT TO MAKE SURE WE USE THE MODULES IN REVERSE ORDER OF DEPENDENCY WHEN DOING A STANDALONE BUILD (THE TOP LEVEL MODULE LAST) - WE NEED TO BUILD THIS LIST UP IN THE LOOP ABOVE, WE ARE NOT DOING IT RIGHT YET



    print 1/0
        


    if standalone and not init_list:
        # TODO: Eventually this should fail if the "main" program - however we decide to indicate
        # that - has no INIT, even if other modules do.
        die("No initialisation code to call!")

    if standalone or ssd:
        # TODO: Ability to locate missing dependencies via some kind of library path;
        # for module compilation we can probably expect these to be modules (but might
        # be nice if we didn't require it), for standalone compilation we would need
        # .pla file and so we would need to invoke compile_pla() on files once located.
        # TODO: We need to check for suitable ordering (or reorder ourselves?) in standalone case
        all_exports = set(val for sublist in exports for val in sublist)
        all_imports = set(val for sublist in imports for val in sublist)
        if not all_imports.issubset(all_exports):
            if False: # TODO: if we can and have augmented files[] from "library"
                files_added = True
            else:
                die("Unsatisfied import(s)") # TODO: show more detail!

# We have a consistent and complete set of files for the task at hand.

# TODO: MORE - WE'RE DONE IF WE'RE NOT GENERATING STANDALONE OR SSD, STANDALONE NEEDS ALL THE STUFF IN PC.PY, SSD MAY BE STANDALONE OR NOT REMEMBER BUT IT'S A QUESTION OF PUTTING THE STANDALONE EXECUTABLE OR ALL THE .MO FILES FOR NON-STANDALONE ONTO SSD
