import struct
import sys

# TODO: I'm using assert where I should probably use something else

# TODO: I imagine it may be quite easy to remove non-exported functions which are never called
# from a module. (Probably it's fine, but do check that if we take the address of a function
# and call it *only* via a pointer, that doesn't trigger removal. I imagine this will "just work"
# because what will count will be having a reference to the function's label, regardless of
# whether that reference appears with a CALL opcode or not.)

def read_u8(f):
    return struct.unpack('<B', f.read(1))[0]

def read_u16(f):
    return struct.unpack('<H', f.read(2))[0]

def read_dci(f):
    s = ''
    while True:
        c = read_u8(f)
        if (c & 0x80) == 0:
            break
        s += chr(c & 0x7f)
    # TODO: Handling 0 like this is a bit of a hack really, but it makes things
    # easier.
    if c != 0:
        s += chr(c)
    return s

def dci_bytes(s):
    result = ''
    for c in s[0:-1]:
        result += '$%02X,' % (ord(c) | 0x80)
    result += '$%02X' % ord(s[-1])
    return result

# TODO: All the 'dump' type functions should probably have a target-type in the name (e.g. acme_dump() or later I will have a binary_dump() which outputs a module directly), and they should probably take a 'file' object which they write to, rather than the current mix of returning strings and just doing direct print() statements

class Label:
    # TODO: Perhaps instead of callers supplying a name, they should specify a prefix and this class uses an internal 'static' counter (a dictionary keyed by prefix with a default value of 0, probably) to assign a name. That way we should be completely safe from the confusion of duplicate labels.
    def __init__(self, name):
        self.name = name

    def acme_reference(self):
        return "!WORD\t%s+0" % (self.name,)

    def acme_rld(self, fixup_label, esd):
        return ("\t!BYTE\t$81\t\t\t; INTERNAL FIXUP\n" +
                "\t!WORD\t%s-_SEGBEGIN\n" +
                "\t!BYTE\t$00") % (fixup_label.name,)

class ExternalReference:
    def __init__(self, external_name, offset):
        self.external_name = external_name
        self.offset = offset

    def acme_reference(self):
        return "!WORD\t%d\t\t\t; %s+%d" % (self.offset, self.external_name, self.offset)

    def acme_rld(self, fixup_label, esd):
        return ("\t!BYTE\t$91\t\t\t; EXTERNAL FIXUP\n" +
                "\t!WORD\t%s-_SEGBEGIN\n" +
                "\t!BYTE\t%d\t\t\t; ESD INDEX (%s)") % (fixup_label.name, esd.get_index(self.external_name), self.external_name)

class ESD:
    def __init__(self):
        self.dict = {}

    def get_index(self, external_name):
        esd_entry = self.dict.get(external_name)
        if esd_entry is None:
            esd_entry = (0x10, len(self.dict))
            self.dict[external_name] = esd_entry
        return esd_entry[1]

    def dump(self):
        print(";\n; EXTERNAL/ENTRY SYMBOL DICTIONARY\n;")
        # TODO: I think the current PLASMA VM will be fine, as it searches the whole ESD every
        # time, but this should probably output the ESD entries in order of their index, not
        # the arbitrary order they appear in the dictionary iteration.
        for external_name, esd_entry in self.dict.items():
            print("\t; DCI STRING: %s" % external_name)
            print("\t!BYTE\t%s" % dci_bytes(external_name))
            print("\t!BYTE\t$%02X\t\t\t; %s" % (esd_entry[0], "EXTERNAL SYMBOL FLAG" if esd_entry[0] == 0x10 else "ENTRY SYMBOL FLAG")) # TODO: Bit crap assuming if it's not 0x10 it's 0x08
            print("\t!WORD\t%d\t\t\t; ESD INDEX" % (esd_entry[1]))
        print("\t!BYTE\t$00\t\t\t; END OF ESD")

class LabelledBlob:
    def __init__(self, blob):
        self.blob = blob
        self.labels = [[] for _ in range(len(self.blob))]
        self.references = [None] * len(self.blob)

    def __getitem__(self, key):
        return self.blob[key]

    def label(self, key, lbl):
        #print('QQQ %s' % (type(key)))
        #print('YYY %d %s' % (key, lbl.name))
        #print('AAA %r' % self.labels[key])
        self.labels[key].append(lbl)
        #print('BBB %r' % self.labels[key])
        #print('ZZZ %d' % (len(self.labels[key])))
        #print('QPP %r' % (self.labels))

    def label_or_get(self, key, name):
        if not self.labels[key]:
            self.labels[key].append(Label(name))
        return self.labels[key][0]

    def reference(self, key, reference):
        assert not self.references[key]
        self.references[key] = reference 

    def read_u16(self, key):
        # TODO: Best way to write this?!
        return ord(self[key]) | (ord(self[key+1]) << 8)

    # TODO: This will probably need to evolve quite a bit and may not be used
    # eventually once we have nicer output formats (I imagine one output format
    # even in final vsn will be suitable for passing to ACME to generate a
    # module)
    def dump(self):
        i = 0
        fixup_count = 0
        fixups = []
        while i < len(self.blob):
            if not self.references[i]:
                #print('SFTODO XXX %d %d %d' % (i, len(self.labels), len(self.labels[i])))
                for label in self.labels[i]:
                    print('%s' % label.name)
                print('\t!BYTE\t$%02X' % (ord(self.blob[i]),))
            else:
                reference = self.references[i]
                assert not self.labels[i]
                fixup_label = Label('_F%03d' % fixup_count)
                fixup_count += 1
                fixups.append((reference, fixup_label))
                print('%s\t%s' % (fixup_label.name, reference.acme_reference()))
                i += 1
                assert not self.labels[i]
                assert not self.references[i]
            i += 1

        # TODO: Eventually we may want the blob to pass the RLD/ESD stuff it wants to emit to
        # some other object; this might (though we'd need to be careful about INIT-combining)
        # for example allow us to merge two modules into a single module. (More immediately
        # usefully, I want to be able to chop up the initial single blob into sub-blobs, e.g.
        # one per bytecode function, and then emit multiple such blobs into the final output.)

        print(";\n; RE-LOCATEABLE DICTIONARY\n;")
        # TODO: Need to emit _C RLD entries
        esd = ESD()
        for reference, fixup_label in fixups:
            print(reference.acme_rld(fixup_label, esd))
        print("\t!BYTE\t$00\t\t\t; END OF RLD")
        esd.dump()

with open('../rel/PLASM#FE1000', 'rb') as f:
    seg_size = read_u16(f)
    magic = read_u16(f)
    assert magic == 0x6502
    sysflags = read_u16(f)
    subseg_abs = read_u16(f)
    defcnt = read_u16(f)
    init_abs = read_u16(f)

    import_names = []
    while True:
        import_name = read_dci(f)
        if not import_name:
            break
        import_names.append(import_name)

    blob_offset = f.tell()
    blob_size = (seg_size + 2) - blob_offset
    blob = LabelledBlob(f.read(blob_size))

    rld = []
    while True:
        c = read_u8(f)
        if c == 0:
            break
        rld_type = c
        rld_word = read_u16(f)
        rld_byte = read_u8(f)
        rld.append((rld_type, rld_word, rld_byte))

    esd = []
    while True:
        esd_name = read_dci(f)
        if not esd_name:
            break
        esd_flag = read_u8(f)
        esd_index = read_u16(f)
        esd.append((esd_name, esd_flag, esd_index))

    #print(seg_size)
    #print(import_names)
    #print(rld)
    #print(esd)

org = 4094

doing_code_table_fixups = True
bytecode_function_labels = []
for i, (rld_type, rld_word, rld_byte) in enumerate(rld):
    if rld_type == 0x02: # code table fixup
        assert doing_code_table_fixups
        assert rld_byte == 0
        blob_index = rld_word - org - blob_offset
        label = Label('_C%03d' % i)
        bytecode_function_labels.append(label)
        blob.label(blob_index, label)
        #print blob[blob_index]
    else:
        doing_code_table_fixups = False
        addr = (rld_word + 2) - blob_offset
        star_addr = blob.read_u16(addr) # TODO: terrible name...
        # cmd.pla just checks rld_type & 0x10, but let's be paranoid and check
        # for precise values for now.
        if rld_type == 0x91: # external fixup
            target_esd_index = rld_byte
            reference = None
            for esd_name, esd_flag, esd_index in esd: # TODO: We could have a dictionary keyed on esd_index
                if esd_index == target_esd_index:
                    # TODO: This is not really right; it will emit a !WORD _EFOO+4 thing in the
                    # dump, but these really are fundamentally different and need to emit just the '4'                     # but trigger emission an external fixup.

                    reference = ExternalReference(esd_name, star_addr)
                    break
            assert label
            blob.reference(addr, reference)
        elif rld_type == 0x81: # internal fixup
            assert rld_byte == 0
            blob_index = star_addr - org - blob_offset
            # TODO? label would be _C or _D in compiler output, we can't tell
            # and don't strictly care (I think). Perhaps use _I for internal?
            # TODO: Perhaps have a separate count starting at 0 for these? If so, label_or_get should probably be responsible for incrementing that count to avoid gaps.
            label = blob.label_or_get(blob_index, '_T%03d' % i)
            blob.reference(addr, label)
        else:
            assert False

blob.dump()
