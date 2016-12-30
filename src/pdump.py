from __future__ import print_function

hexdump_width = 16

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

    def annotate(self, start, end, text):
        a = Annotation(start, end, text)
        self.annotations.append(a)

    def walk(self):
        header = 0
        self.annotate(0, 1, "modsize"); modsize = self.wordrel(0)
        moddep = header + 1
        self.annotate(2, 3, "magic number")
        defofst = modsize
        if self.wordrel(2) == 0xda7e:
            self.annotate(6, 7, "defofst"); defofst = self.wordrel(6)
            self.annotate(8, 9, "defcnt"); defcnt = self.wordrel(8)
            self.annotate(10, 11, "init"); init = self.wordrel(10)
            moddep = header + 12
            
            # Load module dependencies
            while self.byterel(moddep):
                s = self.dcistrrel(moddep)
                self.annotate(moddep, moddep + len(s) - 1, "module dependency: " + s)
                moddep += len(s)
            self.annotate(moddep, moddep, "end of module dependency list")

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

        self.annotations.sort(key=lambda a: a.start)
        prev_end = -1
        i = 0
        for a in self.annotations:
            if a.start <= prev_end:
                print("skipping overlapping annotation: %s" % a)
                continue
            prev_end = a.end
            if i < a.start:
                self.hexdump(i, a.start - 1)
                i = a.start
            self.hexdump(i, a.end, a.text)
            i = a.end + 1
        if i < len(self.data):
            self.hexdump(i, len(self.data) - 1)




module = Module("STDIO#FE1000")
module.dump()
