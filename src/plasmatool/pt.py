import struct
import sys

# TODO: I'm using assert where I should probably use something else

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

class LabelledBlob:
    def __init__(self, blob):
        self.blob = blob
        self.labels = [''] * len(self.blob)
        self.label_references = [''] * len(self.blob)

    def __getitem__(self, key):
        return self.blob[key]

    def label(self, key, name):
        assert not self.labels[key]
        self.labels[key] = name

    def label_or_get(self, key, name):
        if not self.labels[key]:
            self.labels[key] = name
        return self.labels[key]

    def reference_label(self, key, name):
        assert not self.label_references[key]
        self.label_references[key] = name

    def read_u16(self, key):
        # TODO: Best way to write this?!
        return ord(self[key]) | (ord(self[key+1]) << 8)

    # TODO: This will probably need to evolve quite a bit and may not be used
    # eventually once we have nicer output formats (I imagine one output format
    # even in final vsn will be suitable for passing to ACME to generate a
    # module)
    def dump(self):
        i = 0
        while i < len(self.blob):
            if not self.label_references[i]:
                print('%s\t!BYTE $%02X' % (self.labels[i], ord(self.blob[i])))
            else:
                print('%s\t!WORD %s $%02X, $%02X' % (self.labels[i], self.label_references[i], ord(self.blob[i]), ord(self.blob[i+1])))
                i += 1
                assert not self.labels[i]
                assert not self.label_references[i]
            i += 1

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
for i, (rld_type, rld_word, rld_byte) in enumerate(rld):
    if rld_type == 0x02: # code table fixup
        assert doing_code_table_fixups
        assert rld_byte == 0
        blob_index = rld_word - org - blob_offset
        blob.label(blob_index, '_C%03d' % i)
        #print blob[blob_index]
    else:
        doing_code_table_fixups = False
        addr = (rld_word + 2) - blob_offset
        star_addr = blob.read_u16(addr) # TODO: terrible name...
        # cmd.pla just checks rld_type & 0x10, but let's be paranoid and check
        # for precise values for now.
        if rld_type == 0x91: # external fixup
            target_esd_index = rld_byte
            label = None
            for esd_name, esd_flag, esd_index in esd: # TODO: We could have a dictionary keyed on esd_index
                if esd_index == target_esd_index:
                    # TODO: This is not really right; it will emit a !WORD _EFOO+4 thing in the
                    # dump, but these really are fundamentally different and need to emit just the '4'                     # but trigger emission an external fixup.
                    label = '_E_%s+%d' % (esd_name, star_addr)
                    break
            assert label
            blob.reference_label(addr, label)
        elif rld_type == 0x81: # internal fixup
            assert rld_byte == 0
            blob_index = star_addr - org - blob_offset
            # TODO? label would be _C or _D in compiler output, we can't tell
            # and don't strictly care (I think). Perhaps use _I for internal?
            # TODO: Perhaps have a separate count starting at 0 for these?
            label = blob.label_or_get(blob_index, '_T%03d' % i)
            blob.reference_label(addr, label)
        else:
            assert False

blob.dump()
