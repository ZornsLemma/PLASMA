from __future__ import print_function

symtab = [
    ("CMDSYS", "@version"),
    ("CALL", "@call"),
    ("PUTC", "@putc"),
    ("PUTLN", "@putln"),
    ("PUTS", "@puts"),
    ("PUTB", "@prbyte"), # TODO: Change @prbyte to @putb?
    ("PUTH", "@prword"), # TODO: Change @prword to @puth?
    ("GETC", "@getc"),
    ("GETS", "@gets"),
    ("HEAPMARK", "@heapmark"),
    ("HEAPAVAIL", "@heapavail"),
    ("HEAPALLOC", "@heapalloc"),
    ("XHEAPALLOC", "@xheapalloc"),
    ("HEAPALLOCALIGN", "@heapallocalign"),
    ("HEAPRELEASE", "@heaprelease"),
    ("MEMSET", "@memset"),
    ("MEMCPY", "@memcpy"),
    ("STRCPY", "@strcpy"),
    ("STRCAT", "@strcat"),
    ("SEXT", "@sext"),
    ("ISUGT", "@isugt"),
    ("ISUGE", "@isuge"),
    ("ISULT", "@isult"),
    ("ISULE", "@isule"),
    ("MODLOAD", "@modload"), # SFTODO: DELETE??
    # SFTODO: DELETE? ("MODEXEC", "@modexec"),
    ("MACHID", "@machid"), # SFTODO: BE GOOD TO TEST THIS STILL WORKS...
    ("SETJMP", "@setjmp"),
    ("SETJMP2", "@setjmp2"),
    ("LONGJMP", "@longjmp"),
    ("PRBYTE", "@prbyte"),
    ("OSERROR", "@oserror"),
    ("CALL_OSCLI", "@call_oscli"),
    ("STOCR", "@stocr"),
    ("MODE", "@mode"),
    ("CALLALLOCA", "@callalloca"),
    ("MODNAME", "@modname"),
    ("DIVMOD", "@divmod"),
    ("PUTI", "@puti"),
    ("TOUPPER", "@toupper"),
]

print("// AUTOGENERATED; DO NOT EDIT THIS FILE - edit makesymtab.py instead\n")

print("// Initial symbol table")
start = "byte symtbl[] = "
for (name, value) in symtab:
    s = start
    start = "byte = "
    sep = ""
    for i, c in enumerate(name):
        if i < len(name) - 1:
            b = ord(c) | 0x80
        else:
            b = ord(c)
        s += sep + ("$%2x" % b)
        sep = ", "
    print(s + "; word = " + value + " // " + name)

print("byte = $01 // end of symbol table chunk")
print("word = lowsymtblchunk // next symbol table chunk")
