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
    assert False

files = ['samplesrc/hanoi.pla']
standalone = False
ssd = False

imports = [None] * len(files)
exports = [None] * len(files)
init_list = []

files_added = True
while files_added:
    files_added = False

    for i in range(len(files)):
        ok = False
        filename, extension = os.path.splitext(files[i])
        extension = extension.lower()
        if extension == '.pla':
            files[i] = compile_pla(files[i])
            ok = True
        # TODO: we should allow #FEnnnn as well as .mo
        elif extension in ('.a', '.mo'):
            if standalone:
                die("Invalid input for standalone build: " + files[i])
            ok = True
        elif extension == '.sa':
            if not standalone:
                die("Invalid input for module build: " + files[i])
            ok = True
        if not ok:
            die("Invalid input: " + files[i])

        if standalone and imports[i] is None:
            imports[i] = TODO
            exports[i] = TODO
            init_list.append(TODO) # TODO may not be anything to append

        if extension == '.a':
            files[i] = assemble(files[i])
            if ssd:
                imports[i] = TODO
                exports[i] = TODO

    for i in range(len(files)):
        print files[i]
        print imports[i]
        print exports[i]
        print

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
