# TODO: Might be nice if this could disassemble bytecode

from __future__ import print_function

import sys

hexdump_width = 4
MODADDR = 0x1000

# Modules are assembled at 4094, so dumping as though the first byte
# of the file has this offset makes the raw hex offsets clearer.
# However, sometimes it might be simpler if the offset shown is the
# offset within the file, i.e. this is 0.
hexdump_offset = 4094

def comma_list(l):
    s = ""
    sep = ""
    for i in l:
        s += sep + i
        sep = ", "
    return s

def format_size(bytes):
    return "&%04x bytes/%.1fKB" % (bytes, bytes / 1024.0)

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

    def get(self, text):
        for a in self.annotations:
            if a.text == text:
                assert a.start == a.end
                return a.start
        assert False, "Can't get '" + text + "'"

    def walk(self):
        da_labels = {}
        header = 0
        rdlen = len(self.data)
        self.annotate(0, 1, "modsize"); modsize = self.wordrel(0)
        moddep = header + 1
        self.annotate(2, 3, "magic number")
        defofst = modsize
        init = 0

        if self.wordrel(2) == 0x6502:
            print('SFTODO')
            self.annotate_point(modsize+2, "segend")
            self.annotate(4, 5, "system flags")
            defofst = self.wordrel(6)
            self.annotate(6, 7, "defofst (subseg ptr)")
            self.annotate_point(defofst - (MODADDR-2), "subseg")
            self.annotate(8, 9, "defcnt"); defcnt = self.wordrel(8)
            self.annotate(10, 11, "init ptr"); init = self.wordrel(10)
            moddep = header + 12
            
            # Load module dependencies
            while self.byterel(moddep):
                s = self.dcistrrel(moddep)
                print('SFTODO2', s)
                self.annotate(moddep, moddep + len(s) - 1, "dependency: " + s)
                moddep += len(s)
            self.annotate(moddep, moddep, "dependency end marker")

            # Init def table
            deftbl = []

        # Alloc heap space for relocated module (data + bytecode)
        heap = 0
        moddep = moddep + 1 - header + heap
        modfix = moddep - (heap + 2)
	self.annotate_point(modfix, "TODOMODFIX")
        modsize = modsize - modfix
        rdlen = rdlen - modfix - 2
        modaddr = moddep
        self.annotate_point(modaddr, "modaddr")
        # At runtime, the first byte "permanently" stored on the heap is modaddr;
        # the loaded file is memcpy()ed down to overwrite the header.
        self.annotate_point(modaddr + rdlen, "end")

        # Apply all fixups and symbol import/export
        modfix = modaddr - modfix
        bytecode = defofst + modfix - MODADDR
        self.annotate_point(bytecode, "bytecode")
        modend = modaddr + modsize
        self.annotate_point(modend, "modend")
        rld = modend # Re-Locatable Directory
        self.annotate_point(rld, "rld")
        esd = rld # Extern+Entry Symbol Directory
        # Scan to end of ESD^W^W^Wstart of ESD (skipping RLD)
        while self.byterel(esd):
            esd += 4
        self.annotate(esd, esd, "RLD end marker")
        esd += 1
        self.annotate_point(esd, "esd")

        # Populate esd_list
        esd_list = []
        p = esd
        while self.byterel(p):
            sym = p
            s = self.dcistrrel(p)
            esd_list.append(s)
            p += len(s)
            p += 3


        # Run through the Re-Location Dictionary
        while self.byterel(rld):
            rld_type = self.byterel(rld)
            s = []
            if rld_type & 0x02:
                s.append("bytecode def")
            else:
                if rld_type & 0x80:
                    s.append("word-sized")
                else:
                    s.append("byte-sized")
                if rld_type & 0x10:
                    s.append("EXTERN fixup")
                else:
                    s.append("INTERN fixup")
            self.annotate(rld, rld, "RLD entry type (" + comma_list(s) + ")")
            if rld_type & 0x02:
                # This is a bytecode def entry - add it to the def directory
                def_addr = self.wordrel(rld+1) - defofst + bytecode
                self.annotate(rld+1, rld+2, "declare bytecode_def_%d at %04x" % (len(deftbl), hexdump_offset + def_addr))
                self.annotate(rld+3, rld+3, "-")
                self.annotate_point(def_addr, "bytecode_def_%d" % len(deftbl))
                deftbl.append(def_addr)
            else:
                addr = self.wordrel(rld+1) + modfix
                if addr < modaddr:
                    self.annotate(rld+1, rld+2, "fix up at %04x (skipped, header)" % (hexdump_offset + addr))
                else:
                    if rld_type & 0x80:
                        fixup = self.wordrel(addr)
                        s = "word"
                    else:
                        fixup = self.byterel(addr)
                        s = "byte"
                    if rld_type & 0x10: # EXTERN reference
                        index = self.byterel(rld+3)
                        print('SFTODO1', index, len(esd_list))
                        extern_name = esd_list[index]
                        self.annotate(addr, addr+1, "%s (extern)+%d (fixed up by RLD entry at %04x)" % (extern_name, fixup, hexdump_offset + rld))
                        self.annotate(rld+1, rld+2, "EXTERN fix up at %04x" % (hexdump_offset + addr))
                        self.annotate(rld+3, rld+3, "EXTERN ESD index %d (= %s)" % (index, extern_name))
                    else: # INTERN fixup
                        assert rld_type & 0x80
                        fixup = fixup + modfix - MODADDR
                        if fixup < bytecode:
                            target = hexdump_offset + fixup
                            if target not in da_labels:
                                da_labels[target] = "da%d" % len(da_labels)
                                self.annotate_point(fixup, da_labels[target])
                            target_label = da_labels[target]
                            self.annotate(rld+1, rld+2, "INTERN fix up at %04x to data/assembly %s at %04x" % (hexdump_offset + addr, target_label, target))
                            self.annotate(addr, addr+1, "%s (data/assembly at %04x, fixed up by RLD entry at %04x)" % (target_label, target, hexdump_offset + rld))
                        else:
                            index = deftbl.index(fixup)
                            self.annotate(rld+1, rld+2, "INTERN fix up at %04x to bytecode_def_%d at %04x" % (hexdump_offset + addr, index, hexdump_offset + fixup))
                            self.annotate(addr, addr+1, "bytecode_def_%d (fixed up)" % index)
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
                    self.annotate(esd+1, esd+2, "ESD reference to assembly at %04x" % (hexdump_offset + addr))
                    self.annotate_point(addr, s)
                else:
                    index = deftbl.index(addr)
                    self.annotate(esd+1, esd+2, "ESD reference to bytecode_def_%d at %04x" % (index, hexdump_offset + addr))
            else:
                self.annotate(esd, esd, "ESD type (ignored)")
            esd += 3
        self.annotate(esd, esd, "ESD end marker")

        # Call init routine if it exists
        if init != 0:
            def_addr = init - defofst + bytecode
            self.annotate_point(def_addr, "init")

    def hexdump(self, start, end, text=""):
        line_addr = "%04x:" % (hexdump_offset + start)
        count = 0
        hex = ""
        anonymous = not text
        while start <= end:
            hex += "%02x " % self.data[start]
            start += 1
            count += 1
            if count % hexdump_width == 0 or start > end:
                print("\t%5s %-*s %s" % (line_addr, hexdump_width*3, hex, text))
                if anonymous:
                    line_addr = "%04x:" % (hexdump_offset + start)
                else:
                    line_addr = ""
                text = ""
                count = 0
                hex = ""

    def dump(self):
        self.annotations.sort(key=lambda a: (a.start, a.end))
        prev_end = -1
        i = 0
        for a in self.annotations:
            if i < a.start:
                self.hexdump(i, a.start - 1)
                i = a.start
            if a.start == a.end:
                print(a.text)
            else:
                self.hexdump(i, a.end - 1, a.text)
                i = a.end
        if i < len(self.data):
            self.hexdump(i, len(self.data) - 1)

        resident_size = self.get("segend") - self.get("modaddr")
        print("\nMemory resident size: %s" % format_size(resident_size))
        # TODO: Could print sub-sizes showing assembler and bytecode sizes,
        # as these count against different memory areas on PLAS128.
        print("Size on disc:         %s" % format_size(len(self.data)))



module = Module(sys.argv[1])
module.dump()
