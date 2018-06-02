import collections
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
    __next = collections.defaultdict(int)

    def __init__(self, prefix):
        i = Label.__next[prefix]
        self.name = '%s%04d' % (prefix, i)
        Label.__next[prefix] += 1

    def acme_reference(self):
        return "!WORD\t%s+0" % (self.name,)

    def acme_rld(self, fixup_label, esd):
        return ("\t!BYTE\t$81\t\t\t; INTERNAL FIXUP\n" +
                "\t!WORD\t%s-_SEGBEGIN\n" +
                "\t!BYTE\t$00") % (fixup_label.name,)

    # TODO: Seems wrong to need this variant function, but let's just get
    # things going for the moment
    def acme_rld2(self, fixup_label, esd):
        return ("\t!BYTE\t$02\t\t\t; CODE TABLE FIXUP\n" +
                "\t!WORD\t%s\n" +
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
                "\t!BYTE\t%d\t\t\t; ESD INDEX (%s)") % (fixup_label.name, esd.get_index(self.external_name, 0x10), self.external_name)

class RLD:
    def __init__(self):
        self.bytecode_function_labels = []
        self.fixups = [] # TODO: poor name?

    def get_bytecode_function_label(self):
        label = Label('_C')
        self.bytecode_function_labels.append(label)
        return label

    def add_fixup(self, reference, fixup_label):
        self.fixups.append((reference, fixup_label))

    def dump(self):
        for bytecode_function_label in self.bytecode_function_labels:
            print(bytecode_function_label.acme_rld2(bytecode_function_label, None))

        # TODO: It *may* be the case that all the non-bytecode fixups should come together, so that
        # the fast fixup case inside reloc() can handle them all sequentially. This may not make
        # a huge load time different, but it's probably a good idea - especially as output from
        # the standard compiler probably does this anyway.
        for reference, fixup_label in self.fixups:
            print(reference.acme_rld(fixup_label, new_esd))
        print("\t!BYTE\t$00\t\t\t; END OF RLD")


class ESD:
    def __init__(self):
        self.dict = {}

    def get_index(self, external_name, flag):
        esd_entry = self.dict.get(external_name)
        if esd_entry is None:
            esd_entry = (flag, len(self.dict))
            self.dict[external_name] = esd_entry
        return esd_entry[1]

    def dump(self):
        print(";\n; EXTERNAL/ENTRY SYMBOL DICTIONARY\n;")
        # TODO: I think the current PLASMA VM will be fine, as it searches the whole ESD every
        # time, but this should probably output the ESD entries in order of their index, not
        # the arbitrary order they appear in the dictionary iteration.
        # TODO: Similarly, the actual PLASMA compiler seems to put all the EXTERNAL SYMBOL FLAG
        # entries first - I think this will not break the VM, but it would be good to be compatible.
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

    def __len__(self):
        return len(self.blob)

    def slice(self, start, end):
        # SFTODO: Should use a proper ctor
        b = LabelledBlob(self.blob[start:end])
        b.labels = self.labels[start:end]
        b.references = self.references[start:end]
        return b

    def label(self, key, lbl):
        #print('QQQ %s' % (type(key)))
        #print('YYY %d %s' % (key, lbl.name))
        #print('AAA %r' % self.labels[key])
        self.labels[key].append(lbl)
        #print('BBB %r' % self.labels[key])
        #print('ZZZ %d' % (len(self.labels[key])))
        #print('QPP %r' % (self.labels))

    def label_or_get(self, key, prefix):
        if not self.labels[key]:
            self.labels[key].append(Label(prefix))
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
    def dump(self, rld, esd, needs_code_table_fixup):
        print("; SFTODO BLOB START")
        i = 0
        fixup_count = 0
        if needs_code_table_fixup:
            label = rld.get_bytecode_function_label()
            print(label.name)
        while i < len(self.blob):
            if not self.references[i]:
                #print('SFTODO XXX %d %d %d' % (i, len(self.labels), len(self.labels[i])))
                for label in self.labels[i]:
                    print('%s' % label.name)
                print('\t!BYTE\t$%02X' % (ord(self.blob[i]),))
            else:
                reference = self.references[i]
                assert not self.labels[i]
                fixup_label = Label('_F')
                fixup_count += 1
                rld.add_fixup(reference, fixup_label)
                print('%s\t%s' % (fixup_label.name, reference.acme_reference()))
                i += 1
                assert not self.labels[i]
                assert not self.references[i]
            i += 1
        print("; SFTODO BLOB END")


class Module:
    def __init__(self):
        self.sysflags = 0 # SFTODO!?
        self.data_asm_blob = None # SFTODO!?
        self.bytecode_functions = []

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

new_esd = ESD()
for esd_name, esd_flag, esd_index in esd:
    if esd_flag == 0x08: # entry symbol flag, i.e. an exported symbol
        new_esd.get_index(esd_name, esd_flag)

doing_code_table_fixups = True
#bytecode_function_labels = []
bytecode_function_offsets = []
for i, (rld_type, rld_word, rld_byte) in enumerate(rld):
    if rld_type == 0x02: # code table fixup
        assert doing_code_table_fixups
        assert rld_byte == 0
        blob_index = rld_word - org - blob_offset
        bytecode_function_offsets.append(blob_index)
        #label = Label('_C%03d' % i)
        #bytecode_function_labels.append(label)
        #blob.label(blob_index, label)
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
                    reference = ExternalReference(esd_name, star_addr)
                    break
            assert reference
            blob.reference(addr, reference)
        elif rld_type == 0x81: # internal fixup
            assert rld_byte == 0
            blob_index = star_addr - org - blob_offset
            # TODO? label would be _C or _D in compiler output, we can't tell
            # and don't strictly care (I think).
            label = blob.label_or_get(blob_index, '_I')
            blob.reference(addr, label)
        else:
            assert False

init_offset = init_abs - org - blob_offset
#blob.label(init_offset, Label("_INIT"))

new_module = Module()
# TODO: Should probably support proper [a:b] slice overload instead of having slice() fn
new_module.data_asm_blob = blob.slice(0, subseg_abs - org - blob_offset)

#new_module.bytecode_blob = blob.slice(subseg_abs - org - blob_offset, len(blob))
offsets = bytecode_function_offsets + [init_offset, len(blob)]
for start, end in zip(offsets, offsets[1:]):
    bytecode_function_blob = blob.slice(start, end)
    new_module.bytecode_functions.append(bytecode_function_blob)

del blob
del rld
del esd
del defcnt

#blob.label(subseg_abs - org - blob_offset, Label("_SUBSEG"))
#new_module.bytecode_blob.label(0, Label("_SUBSEG"))

print("\t!WORD\t_SEGEND-_SEGBEGIN\t; LENGTH OF HEADER + CODE/DATA + BYTECODE SEGMENT")
print("_SEGBEGIN")
print("\t!WORD\t$6502\t\t\t; MAGIC #")
print("\t!WORD\t%d\t\t\t; SYSTEM FLAGS" % (sysflags,))
print("\t!WORD\t_SUBSEG\t\t\t; BYTECODE SUB-SEGMENT")
print("\t!WORD\t_DEFCNT\t\t\t; BYTECODE DEF COUNT")
print("\t!WORD\t_INIT\t\t\t; MODULE INITIALIZATION ROUTINE")

for import_name in import_names:
    print("\t; DCI STRING: %s" % (import_name,))
    print("\t!BYTE\t%s" % dci_bytes(import_name))
print("\t!BYTE\t$00\t\t\t; END OF MODULE DEPENDENCIES")

new_rld = RLD()
new_module.data_asm_blob.dump(new_rld, new_esd, False)
print("_SUBSEG")
#new_module.bytecode_blob.dump(new_rld, new_esd)
# TODO: Recognising _INIT by the fact it comes last is a bit of a hack - though do note we must *emit* it last however we handle this
# TODO: I am assuming there is an INIT function - if you look at cmd.pla, you can see the INIT address in the header can be 0 in which case there is no INIT function. I don't know if the compiler always generates a stub INIT, but if it does we can probably optimise it away if it does nothing but 'RET' or similar.
for bytecode_function in new_module.bytecode_functions[0:-1]:
    bytecode_function.dump(new_rld, new_esd, True)
print("_INIT")
new_module.bytecode_functions[-1].dump(new_rld, new_esd, False)

defcnt = len(new_module.bytecode_functions)
print("_DEFCNT = %d" % (defcnt,))
print("_SEGEND")
print(";\n; RE-LOCATEABLE DICTIONARY\n;")

new_rld.dump()

new_esd.dump()
