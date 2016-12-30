from __future__ import print_function

import sys

hexdump_width = 16
MODADDR = 0x1000

def comma_list(l):
    s = ""
    sep = ""
    for i in l:
        s += sep + i
        sep = ", "
    return s

class Annotation:
    def __init__(self, start, end, text):
        assert start <= end
        self.start = start
        self.end = end
        self.text = text

class Module:
    def __init__(self, filename):
        with open(filename, "rb") as file:
            data = file.read()
            # Munge this once and for all here and hopefully we can isolate
            # Python 2/3 incompatibilities
            self.data = []
            for d in data:
                self.data.append(ord(d))

        self.annotations = []
        self.walk()

    def byterel(self, i):
        return self.data[i]

    def wordrel(self, i):
        return self.data[i] + (self.data[i+1]<<8)

    def dcistrrel(self, i):
        s = ""
        length = 0
        while self.byterel(i) & 0x80:
            s += chr(self.byterel(i) & ~0x80)
            i += 1
        s += chr(self.byterel(i))
        return s

    # "label" annotation at point addr
    def annotate_point(self, addr, text):
        a = Annotation(addr, addr, text)
        self.annotations.append(a)

    # range annotation: [start, end] (i.e. inclusive)
    def annotate(self, start, end, text):
        a = Annotation(start, end + 1, text)
        self.annotations.append(a)

    def walk(self):
        header = 0
        rdlen = len(self.data)
        self.annotate(0, 1, "modsize"); modsize = self.wordrel(0)
        moddep = header + 1
        self.annotate(2, 3, "magic number")
        defofst = modsize
        init = 0

        if self.wordrel(2) == 0xda7e:
            self.annotate_point(modsize+2, "SEGEND")
            self.annotate(4, 5, "system flags")
            defofst = self.wordrel(6)
            self.annotate(6, 7, "defofst => %04x" % (defofst - (MODADDR-2)))
            self.annotate(8, 9, "defcnt"); defcnt = self.wordrel(8)
            self.annotate(10, 11, "init"); init = self.wordrel(10)
            moddep = header + 12
            
            # Load module dependencies
            while self.byterel(moddep):
                s = self.dcistrrel(moddep)
                self.annotate(moddep, moddep + len(s) - 1, "dependency: " + s)
                moddep += len(s)
            self.annotate(moddep, moddep, "dependency end marker")

            # Init def table
            deftbl = []

        # Alloc heap space for relocated module (data + bytecode)
        heap = 0
        moddep = moddep + 1 - header + heap
        modfix = moddep - (heap + 2)
        modsize = modsize - modfix
        rdlen = rdlen - modfix - 2
        modaddr = moddep

        # Apply all fixups and symbol import/export
        modfix = modaddr - modfix
        bytecode = defofst + modfix - MODADDR
        modend = modaddr + modsize
        rld = modend # Re-Locatable Directory
        esd = rld # Extern+Entry Symbol Directory
        # Scan to end of ESD
        while self.byterel(esd):
            esd += 4
        self.annotate(esd, esd, "ESD end marker")
        esd += 1

        # Run through the Re-Location Dictionary
        while self.byterel(rld):
            rld_type = self.byterel(rld)
            s = []
            if rld_type & 0x02:
                s.append("bytecode def")
            else:
                if rld_type & 0x80:
                    s.append("word-sized fixup")
                else:
                    s.append("byte-sized fixup")
                if rld_type & 0x10:
                    s.append("EXTERN reference")
                else:
                    s.append("INTERN fixup")
            self.annotate(rld, rld, "RLD entry type (" + comma_list(s) + ")")
            if rld_type & 0x02:
                # This is a bytecode def entry - add it to the def directory
                def_addr = self.wordrel(rld+1) - defofst + bytecode
                self.annotate(rld+1, rld+2, "RLD bytecode def %d, %04x" % (len(deftbl), def_addr))
                deftbl.append(def_addr)
            else:
                addr = self.wordrel(rld+1) + modfix
                if addr < modaddr:
                    self.annotate(rld+1, rld+2, "RLD reference to %04x, skipped" % addr)
                else:
                    if rld_type & 0x80:
                        fixup = self.wordrel(addr)
                    else:
                        fixup = self.byterel(addr)
                    if rld_type & 0x10: # EXTERN reference
                        self.annotate(rld+1, rld+2, "RLD reference to %04x" % addr)
                        index = self.byterel(rld+3)
                        self.annotate(rld+3, rld+3, "RLD EXTERN reference index %d (= %s)" % (index, "TODO"))
                        fixup = 0xffff # SFTODO
                    else: # INTERN fixup
                        fixup = fixup + modfix - MODADDR
                        if fixup < bytecode:
                            self.annotate(rld+1, rld+2, "RLD reference to %04x, skipped" % fixup)
                        else:
                            index = deftbl.index(fixup)
                            self.annotate(rld+1, rld+2, "RLD reference to %04x (deftbl entry %d = TODO)" % (fixup, index))
                    if rld_type & 0x80:
                        self.annotate(addr, addr + 1, "RLD word fixup to %04x" % fixup)
                    else:
                        self.annotate(addr, addr, "RLD byte fixup to %02x" % fixup)
            rld += 4

        # Run through the External/Entry Symbol Directory
        while self.byterel(esd):
            sym = esd
            s = self.dcistrrel(esd)
            esd += len(s)
            self.annotate(sym, esd-1, "ESD symbol name: " + s)
            esd_type = self.byterel(esd)
            if esd_type & 0x08:
                self.annotate(esd, esd, "ESD type (EXPORT symbol)")
                addr = self.wordrel(esd+1) + modfix - MODADDR
                if addr < bytecode:
                    TODO
                else:
                    index = deftbl.index(addr)
                    self.annotate(esd+1, esd+2, "ESD reference to %04x (deftbl entry %d = TODO)" % (addr, index))
            else:
                self.annotate(esd, esd, "ESD type (ignored)")
            # TODO
            esd += 3

        # Call init routine if it exists
        if init != 0:
            def_addr = init - defofst + bytecode
            self.annotate(def_addr, def_addr, "Start of INIT")

    def hexdump(self, start, end, text=""):
        gap = start % hexdump_width
        line_addr = (start // hexdump_width) * hexdump_width
        s = ("%04x " % line_addr) + ("   " * gap)
        while start <= end:
            s += "%02x " % self.data[start]
            start += 1
            if start % hexdump_width == 0:
                print(s + "  " + text)
                text = ""
                s = "%04x " % start
        if len(s) > 5:
            s += " " * (5 + 3*hexdump_width - len(s)) + "  " + text
            print(s)

    def dump(self):

        header = "     "
        for i in range(hexdump_width):
            header += "%02x " % i
        print(header)

        self.annotations.sort(key=lambda a: (a.start, a.end))
        prev_end = -1
        i = 0
        for a in self.annotations:
            if i < a.start:
                self.hexdump(i, a.start - 1)
                i = a.start
            if a.start == a.end:
                print("     " + "   "*hexdump_width + "  " + a.text)
            else:
                self.hexdump(i, a.end - 1, a.text)
                i = a.end
        if i < len(self.data):
            self.hexdump(i, len(self.data) - 1)




module = Module(sys.argv[1])
module.dump()
