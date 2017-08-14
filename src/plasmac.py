# single .pla -> .mo/#FExxxx file
# single .pla -> SSD with .mo plus any additional .mo required plus VM executable
# multiple .pla -> executable
# multiple .pla -> SSD containing executable
# SSDs may be optionally bootable and will boot "the main module/executable"

def die(s):
    sys.stderr.write(s + '\n')
    sys.exit(1)

def compile_pla(source):
    # TODO: Invokes plasm with appropriate options, returning filename of plasm
    # output - the returned filename will have a .a or .sa extensions depending
    # on whether we're doing standalone build or not
    assert False

files = ['samplesrc/hanoi.pla']
standalone = False
ssd = False

imports = [None] * len(files)
exports = [None] * len(files)
init_list = []

for i in range(len(files)):
    ok = False
    filename, extension = os.path.splitext(files[i])
    extension = extension.lower()
    if extension == '.pla':
        files[i] = compile_pla(files[i]) # TODO: different extn for module/standalone
        ok = True
    elif extension == '.a':
        if standalone:
            die("Invalid input for standalone build: " + files[i])
        ok = True
    elif extension == '.sa':
        if not standalone:
            die("Invalid input for module build: " + files[i])
        ok = True
    if not ok:
        die("Invalid input: " + files[i])

    if standalone:
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
    all_exports = set(val for sublist in exports for val in sublist)
    all_imports = set(val for sublist in imports for val in sublist)
    assert all_imports.issubset(all_exports) # TODO: proper error not assert
