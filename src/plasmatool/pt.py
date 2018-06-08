import abc
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

    def __init__(self, prefix, add_suffix = True):
        if add_suffix:
            i = Label.__next[prefix]
            self.name = '%s%04d' % (prefix, i)
            Label.__next[prefix] += 1
        else:
            self.name = prefix

    def nm(self):
        return self.name

    def acme_reference(self):
        return "\t!WORD\t%s+0" % (self.name,)

    def acme_reference2(self): # SFTODO: HORRIBLE NAMING ETC ETC
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

    def update_used_things(self, used_things):
        # TODO: Use of global label_dict is a bit clunky
        #print('SFTODOXY %d', len(label_dict))
        label_dict[self.name].update_used_things(used_things)

    @classmethod
    def disassemble(cls, bytecode_function, i):
        label = bytecode_function.references[i]
        assert label
        return label, i+2

class ExternalReference:
    def __init__(self, external_name, offset):
        self.external_name = external_name
        self.offset = offset
        
    def nm(self):
        if self.offset:
            return "%s+%d" % (self.external_name, self.offset)
        else:
            return self.external_name

    def acme_reference(self):
        return "\t!WORD\t%d\t\t\t; %s+%d" % (self.offset, self.external_name, self.offset)

    def acme_reference2(self): # SFTODO: HORRIBLE NAMING ETC ETC
        return "!WORD\t%d" % (self.offset,)

    def acme_rld(self, fixup_label, esd):
        return ("\t!BYTE\t$91\t\t\t; EXTERNAL FIXUP\n" +
                "\t!WORD\t%s-_SEGBEGIN\n" +
                "\t!BYTE\t%d\t\t\t; ESD INDEX (%s)") % (fixup_label.name, esd.get_external_index(self.external_name), self.external_name)

    def update_used_things(self, used_things):
        pass

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
        self.entry_dict = {}
        self.external_dict = {}

    def add_entry(self, external_name, reference):
        assert external_name not in self.entry_dict
        self.entry_dict[external_name] = reference

    def get_external_index(self, external_name):
        esd_entry = self.external_dict.get(external_name)
        if esd_entry is None:
            esd_entry = len(self.external_dict)
            self.external_dict[external_name] = esd_entry
        return esd_entry

    def dump(self):
        print(";\n; EXTERNAL/ENTRY SYMBOL DICTIONARY\n;")
        # TODO: I think the current PLASMA VM will be fine, as it searches the whole ESD every
        # time, but this should probably output the ESD entries in order of their index, not
        # the arbitrary order they appear in the dictionary iteration.
        # TODO: Similarly, the actual PLASMA compiler seems to put all the EXTERNAL SYMBOL FLAG
        # entries first - I think this will not break the VM, but it would be good to be compatible.
        for external_name, esd_index in self.external_dict.items():
            print("\t; DCI STRING: %s" % external_name)
            print("\t!BYTE\t%s" % dci_bytes(external_name))
            print("\t!BYTE\t$10\t\t\t; EXTERNAL SYMBOL FLAG")
            print("\t!WORD\t%d\t\t\t; ESD INDEX" % (esd_index,))
        for external_name, reference in self.entry_dict.items():
            print("\t; DCI STRING: %s" % external_name)
            print("\t!BYTE\t%s" % dci_bytes(external_name))
            print("\t!BYTE\t$08\t\t\t; ENTRY SYMBOL FLAG")
            print('\t%s' % (reference.acme_reference(),))
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

    def update_label_dict(self, label_dict):
        for label_list in self.labels:
            for label in label_list:
                label_dict[label.name] = self

    def update_used_things(self, used_things):
        if self in used_things:
            return
        used_things.add(self)
        #print("SFTODO99 %r %r" % (self, len(self.references)))
        #print("SFTODO99 %r" % self.references)
        for reference in self.references:
            if reference:
                reference.update_used_things(used_things)

    # TODO: This will probably need to evolve quite a bit and may not be used
    # eventually once we have nicer output formats (I imagine one output format
    # even in final vsn will be suitable for passing to ACME to generate a
    # module)
    def dump(self, rld, esd):
        print("; SFTODO BLOB START %r" % self)
        i = 0
        fixup_count = 0
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


class Opcode:
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def length(self):
        pass
    

class Byte:
    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return "Byte(%d)" % (self.value,)

    def acme(self):
        return "$%02X" % (self.value,)

    def human(self):
        return "%d" % (self.value,)

    @classmethod
    def disassemble(cls, bytecode_function, i):
        byte = cls(ord(bytecode_function[i]))
        return byte, i+1


class FrameOffset(Byte):
    def human(self):
        return "[%d]" % (self.value,)



class Word:
    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return "Word(%d)" % (self.value,)

    @classmethod
    def disassemble(cls, bytecode_function, i):
        word = Word(ord(bytecode_function[i]) | (ord(bytecode_function[i+1]) << 8))
        return word, i+2

# https://stackoverflow.com/questions/32030412/twos-complement-sign-extension-python
def sign_extend(value, bits):
    sign_bit = 1 << (bits - 1)
    return (value & (sign_bit - 1)) - (value & sign_bit)

local_label_count = 0

class Offset:
    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return "Offset(%s)" % (self.value,)

    @classmethod
    def disassemble(cls, bytecode_function, i, current_pos = None):
        if not current_pos:
            current_pos = i
        value = ord(bytecode_function[i]) | (ord(bytecode_function[i+1]) << 8)
        value = sign_extend(value, 16)
        target = i + value
        global local_label_count
        local_label = '_L%04d' % (local_label_count,)
        #print("; SFTODO ASSIGNING LOCAL LABEL %s" % (local_label,))
        local_label_count += 1
        if target > current_pos:
            bytecode_function.local_target[target].append(local_label)
        elif target < current_pos:
            j = 0
            while j < len(bytecode_function.op_offset):
                if bytecode_function.op_offset[j] == target:
                    bytecode_function.op_offset.insert(j, None)
                    bytecode_function.ops.insert(j, (0xff, [local_label]))
                    j = 99999 # SFTODO ULTRA FOUL
                j += 1
            assert j >= 99999
        return Offset(local_label), i+2



class CaseBlockOffset:
    def __init__(self, label):
        self.label = label

    def __repr__(self):
        return "CaseBlockOffset(%s)" % (self.label,)

    @classmethod
    def disassemble(cls, bytecode_function, i):
        global local_label_count
        local_label = '_L%04d' % (local_label_count,)
        local_label_count += 1
        # SFTODO: THIS NEEDS TO DO SIMILAR STUFF TO OFFSET CLASS I THINK
        cbo = ord(bytecode_function[i]) | (ord(bytecode_function[i+1]) << 8)
        #count = ord(bytecode_function[i + cbo])
        #print('SFTODOCBO %d' % count)
        bytecode_function.special[i + cbo] = local_label # SFTODO HACKY
        return CaseBlockOffset(local_label), i+2


class CaseBlock:
    def __init__(self, table):
        self.table = table

    def __repr__(self):
        return "CaseBlock(%d)" % (len(self.table),)

    @classmethod
    def disassemble(cls, bytecode_function, i):
        count = ord(bytecode_function[i])
        table = []
        for j in range(count):
            k = i + 1 + 4*j
            value = ord(bytecode_function[k]) | (ord(bytecode_function[k+1]) << 8)
            offset, _ = Offset.disassemble(bytecode_function, k+2, i)
            table.append((value, offset))
        return CaseBlock(table), i+1+4*count


class String:
    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return "String(%r)" % (self.value,)

    @classmethod
    def disassemble(cls, bytecode_function, i):
        length = ord(bytecode_function[i])
        s = ''
        for j in range(length):
            s += bytecode_function[i + j + 1]
        return String(s), i + length + 1


def acme_dump_enter(opcode, operands):
    print("\t!BYTE\t$%02X,$%02X,$%02X\t\t; ENTER\t%d,%d" % (opcode, operands[0].value, operands[1].value, operands[0].value, operands[1].value))

def acme_dump_branch(opcode, operands):
    print("\t!BYTE\t$%02X\t\t\t; %s\t%s" % (opcode, opdict[opcode]['opcode'], operands[0].value))
    print("\t!WORD\t%s-*" % (operands[0].value,))

def acme_dump_label(opcode, operands, rld):
    print("\t!BYTE\t$%02X\t\t\t; %s\t%s+0" % (opcode, opdict[opcode]['opcode'], operands[0].nm()))
    fixup_label = Label('_F')
    rld.add_fixup(operands[0], fixup_label)
    print('%s\t%s' % (fixup_label.name, operands[0].acme_reference2()))

def acme_dump_cs(opcode, operands):
    s = operands[0].value
    print("\t!BYTE\t$2E\t\t\t; CS\t%r" % (s,)) # SFTODO: REPR NOT PERFECT BUT WILL DO - IT CAN USE SINGLE QUOTES TO WRAP THE STRING WHICH ISN'T IDEAL
    print("\t!BYTE\t$%02X" % (len(s),))
    while s:
        t = s[0:8]
        s = s[8:]
        print("\t!BYTE\t" + ",".join("$%02X" % ord(c) for c in t))

def acme_dump_sel(opcode, operands):
    global tail
    print("\t!BYTE\t$52\t\t\t; SEL\t%s" % (operands[0].label,))
    print("\t!WORD\t%s-*" % (operands[0].label,))
    #tail.append(local_label)
    #tail.append("\t!BYTE\t$%02X\t\t\t; CASEBLOCK" % (len(operands[0].table),))
    #for value, offset in operands[0].table:
    #    tail.append("\t!WORD\t$%04X" % (value,))
    #    tail.append("\t!WORD\t%s-*" % (offset.value,))

def acme_dump_caseblock(opcode, operands):
    table = operands[0].table
    print("\t!BYTE\t$%02X\t\t\t; CASEBLOCK" % (len(table),))
    for value, offset in table:
        print("\t!WORD\t$%04X" % (value,))
        print("\t!WORD\t%s-*" % (offset.value,))




# TODO: Possibly the disassembly should turn CN into CB or just a 'CONST' pseudo-opcode (which CW/CFFB/MINUSONE would also turn into) and then when we emit bytecode from the disassembly we'd use the optimal one - I have done this, but it many ways it would be cleaner to turn them all into CW not a CONST pseudo-op, and then optimise CW on output instead of optimising this CONST pseudo-op
# TODO: We may well want to have a class FrameOffset deriving from Byte and use that for some operands - this would perhaps do nothing more than use the [n] representation in the comments on assembler output, but might be a nice way to get that for little extra effort
# TODO: Check this table is complete and correct
# TODO: I do wonder if we'd go wrong if we actually had something like '*$3000=42' in a PLASMA program; we seem to be assuming that the operand of some opcodes is always a label, when it *might* be a literal
opdict = {
    0x00: {'opcode': 'CN', 'constfn': lambda bfn, i: (0, i)},
    0x02: {'opcode': 'CN', 'constfn': lambda bfn, i: (1, i)},
    0x04: {'opcode': 'CN', 'constfn': lambda bfn, i: (2, i)},
    0x06: {'opcode': 'CN', 'constfn': lambda bfn, i: (3, i)},
    0x08: {'opcode': 'CN', 'constfn': lambda bfn, i: (4, i)},
    0x0a: {'opcode': 'CN', 'constfn': lambda bfn, i: (5, i)},
    0x0c: {'opcode': 'CN', 'constfn': lambda bfn, i: (6, i)},
    0x0e: {'opcode': 'CN', 'constfn': lambda bfn, i: (7, i)},
    0x10: {'opcode': 'CN', 'constfn': lambda bfn, i: (8, i)},
    0x12: {'opcode': 'CN', 'constfn': lambda bfn, i: (9, i)},
    0x14: {'opcode': 'CN', 'constfn': lambda bfn, i: (10, i)},
    0x16: {'opcode': 'CN', 'constfn': lambda bfn, i: (11, i)},
    0x18: {'opcode': 'CN', 'constfn': lambda bfn, i: (12, i)},
    0x1a: {'opcode': 'CN', 'constfn': lambda bfn, i: (13, i)},
    0x1c: {'opcode': 'CN', 'constfn': lambda bfn, i: (14, i)},
    0x1e: {'opcode': 'CN', 'constfn': lambda bfn, i: (15, i)},
    0x20: {'opcode': 'MINUS1', 'constfn': lambda bfn, i: (-1, i)},
    0x22: {'opcode': 'BREQ', 'operands': (Offset,), 'acme_dump': acme_dump_branch},
    0x24: {'opcode': 'BRNE', 'operands': (Offset,), 'acme_dump': acme_dump_branch},
    0x26: {'opcode': 'LA', 'operands': (Label,), 'acme_dump': acme_dump_label},
    0x28: {'opcode': 'LLA', 'operands': (FrameOffset,)},
    0x2a: {'opcode': 'CB', 'constfn': lambda bfn, i: (ord(bfn[i]), i+1)},
    0x2c: {'opcode': 'CW', 'constfn': lambda bfn, i: (sign_extend(ord(bfn[i]) | (ord(bfn[i+1]) << 8), 16), i+2)}, # SFTODO 999 IS HACK
    0x2e: {'opcode': 'CS', 'operands': (String,), 'acme_dump': acme_dump_cs},
    0x30: {'opcode': 'DROP', 'operands': ()},
    0x34: {'opcode': 'DUP', 'operands': ()},
    0x38: {'opcode': 'ADDI', 'operands': (Byte,)},
    0x3a: {'opcode': 'SUBI', 'operands': (Byte,)},
    0x3c: {'opcode': 'ANDI', 'operands': (Byte,)},
    0x3e: {'opcode': 'ORI', 'operands': (Byte,)},
    0x40: {'opcode': 'ISEQ', 'operands': ()},
    0x42: {'opcode': 'ISNE', 'operands': ()},
    0x44: {'opcode': 'ISGT', 'operands': ()},
    0x46: {'opcode': 'ISLT', 'operands': ()},
    0x48: {'opcode': 'ISGE', 'operands': ()},
    0x4a: {'opcode': 'ISLE', 'operands': ()},
    0x4c: {'opcode': 'BRFLS', 'operands': (Offset,), 'acme_dump': acme_dump_branch},
    0x4e: {'opcode': 'BRTRU', 'operands': (Offset,), 'acme_dump': acme_dump_branch},
    0x50: {'opcode': 'BRNCH', 'operands': (Offset,), 'acme_dump': acme_dump_branch},
    0x52: {'opcode': 'SEL', 'operands': (CaseBlockOffset,), 'acme_dump': acme_dump_sel}, # SFTODO: THIS IS GOING TO NEED MORE CARE, BECAUSE THE OPERAND IDENTIFIES A JUMP TABLE WHICH WE WILL NEED TO HANDLE CORRECTLY WHEN DISASSEMBLY REACHES IT
    0x54: {'opcode': 'CALL', 'operands': (Label,), 'acme_dump': acme_dump_label},
    0x56: {'opcode': 'ICAL', 'operands': ()},
    0x58: {'opcode': 'ENTER', 'operands': (Byte, Byte), 'acme_dump': acme_dump_enter},
    0x5c: {'opcode': 'RET', 'operands': ()},
    0x5a: {'opcode': 'LEAVE', 'operands': (Byte,)},
    0x5e: {'opcode': 'CFFB', 'operands': (Byte,)},
    0x60: {'opcode': 'LB', 'operands': ()},
    0x62: {'opcode': 'LW', 'operands': ()},
    0x64: {'opcode': 'LLB', 'operands': (Byte,)},
    0x66: {'opcode': 'LLW', 'operands': (FrameOffset,)},
    0x68: {'opcode': 'LAB', 'operands': (Label,), 'acme_dump': acme_dump_label},
    0x6e: {'opcode': 'DLW', 'operands': (FrameOffset,)},
    0x6a: {'opcode': 'LAW', 'operands': (Label,), 'acme_dump': acme_dump_label},
    0x6c: {'opcode': 'DLB', 'operands': (FrameOffset,)},
    0x70: {'opcode': 'SB', 'operands': ()},
    0x72: {'opcode': 'SW', 'operands': ()},
    0x74: {'opcode': 'SLB', 'operands': (FrameOffset,)},
    0x76: {'opcode': 'SLW', 'operands': (FrameOffset,)},
    0x78: {'opcode': 'SAB', 'operands': (Label,), 'acme_dump': acme_dump_label},
    0x7a: {'opcode': 'SAW', 'operands': (Label,), 'acme_dump': acme_dump_label},
    0x7c: {'opcode': 'DAB', 'operands': (Label,), 'acme_dump': acme_dump_label},
    0x7e: {'opcode': 'DAW', 'operands': (Label,), 'acme_dump': acme_dump_label},
    0x80: {'opcode': 'LNOT', 'operands': ()},
    0x82: {'opcode': 'ADD', 'operands': ()},
    0x84: {'opcode': 'SUB', 'operands': ()},
    0x86: {'opcode': 'MUL', 'operands': ()},
    0x88: {'opcode': 'DIV', 'operands': ()},
    0x8a: {'opcode': 'MOD', 'operands': ()},
    0x8c: {'opcode': 'INCR', 'operands': ()},
    0x8e: {'opcode': 'DECR', 'operands': ()},
    0x90: {'opcode': 'NEG', 'operands': ()},
    0x92: {'opcode': 'COMP', 'operands': ()},
    0x94: {'opcode': 'BAND', 'operands': ()},
    0x96: {'opcode': 'IOR', 'operands': ()},
    0x98: {'opcode': 'XOR', 'operands': ()},
    0x9a: {'opcode': 'SHL', 'operands': ()},
    0x9c: {'opcode': 'SHR', 'operands': ()},
    0x9e: {'opcode': 'IDXW', 'operands': ()},
    0xa0: {'opcode': 'BRGT', 'operands': (Offset,), 'acme_dump': acme_dump_branch},
    0xa2: {'opcode': 'BRLT', 'operands': (Offset,), 'acme_dump': acme_dump_branch},
    0xa4: {'opcode': 'INCBRLE', 'operands': (Offset,), 'acme_dump': acme_dump_branch},
    0xa8: {'opcode': 'DECBRGE', 'operands': (Offset,), 'acme_dump': acme_dump_branch},
    0xac: {'opcode': 'BRAND', 'operands': (Offset,), 'acme_dump': acme_dump_branch},
    0xae: {'opcode': 'BROR', 'operands': (Offset,), 'acme_dump': acme_dump_branch},
    0xb0: {'opcode': 'ADDLB', 'operands': (FrameOffset,)},
    0xb2: {'opcode': 'ADDLW', 'operands': (FrameOffset,)},
    0xb4: {'opcode': 'ADDAB', 'operands': (Label,), 'acme_dump': acme_dump_label},
    0xb6: {'opcode': 'ADDAW', 'operands': (Label,), 'acme_dump': acme_dump_label},
    0xb8: {'opcode': 'IDXLB', 'operands': (FrameOffset,)},
    0xba: {'opcode': 'IDXLW', 'operands': (FrameOffset,)},
    0xbc: {'opcode': 'IDXAB', 'operands': (Label,), 'acme_dump': acme_dump_label},
    0xbe: {'opcode': 'IDXAW', 'operands': (Label,), 'acme_dump': acme_dump_label},
}


class BytecodeFunction(LabelledBlob):
    # TODO: This seems really really wrong but let's not worry about it for now
    def __init__(self, labelled_blob):
        assert isinstance(labelled_blob, LabelledBlob)
        self.blob = labelled_blob.blob
        self.labels = labelled_blob.labels
        self.references = labelled_blob.references
        self.local_target = [[] for _ in range(len(labelled_blob))] # SFTODO VERY EXPERIMENTAL
        self.special = [None] * len(labelled_blob) # SFTODO VERY EXPERIMENTAL
        self.ops = [] # SFTODO VERY EXPERIMENTAL
        self.op_offset = [] # SFTODO VERY EXPERIMENTAL

    def is_init(self):
        return any(x.name == '_INIT' for x in self.labels[0])

    # TODO: Ultra experimental, I need to be very careful to ensure that any 
    # changes to the disassembled version are reflected when dump() is called.
    def disassemble(self, rld):
        ops = self.ops
        i = 0
        while i < len(self.blob):
            # There should be no labels within a bytecode function. We will later
            # create branch-target labels based on the branch instructions within
            # the function, but those are different.
            assert i == 0 or not self.labels[i]
            for t in self.local_target[i]:
                ops.append((0xff, [t])) # SFTODO MAGIC CONSTANT - 'TARGET' PSEUDO-OPCODE
                self.op_offset.append(None)
            self.op_offset.append(i) # SFTODO SHOULD WE DO THIS EVEN IF SPECIAL?
            special = self.special[i]
            if not special:
                opcode = ord(self.blob[i])
                i += 1
                #print('SFTODOQQ %X' % opcode)
                opdef = opdict[opcode]
                constfn = opdef.get('constfn', None)
                if constfn:
                    operand, i = constfn(self, i)
                    op = (0xfd, [operand]) # SFTODO MAGIC CONSTANT 'CONST' PSEUDO OP
                else:
                    operands = []
                    for operandcls in opdef['operands']:
                        operand, i = operandcls.disassemble(self, i)
                        operands.append(operand)
                    #print(opdef['opcode'], operands)
                    op = (opcode, operands)
                ops.append(op)
            else:
                label = self.special[i]
                operand, i = CaseBlock.disassemble(self, i)
                op = (0xfb, [operand]) # SFTODO MAGIC CONST 'CASEBLOCK' PSEUDO OP
                ops.append(op)

        global tail# SFTODO HACK, SHOULD BE MEMBER OR SOMETHING
        tail = []
        for opcode, operands in ops:
            if opcode == 0xfd:
                value = operands[0]
                if value >= 0 and value < 16:
                    print("\t!BYTE\t$%02X\t\t\t; CN\t%d" % (value << 1, value))
                elif value >= 0 and value < 256:
                    print("\t!BYTE\t$2A,$%02X\t\t\t; CB\t%d" % (value, value))
                elif value == -1:
                    print("\t!BYTE\t$20\t\t\t; MINUS ONE")
                elif value & 0xff00 == 0xff00:
                    print("\t!BYTE\t$5E,$%02X\t\t\t; CFFB\t%d" % (value & 0xff, value))
                else:
                    print("\t!BYTE\t$2C,$%02X,$%02X\t\t; CW\t%d" % (value & 0xff, (value & 0xff00) >> 8, value))
            elif opcode == 0xff:
                print("%s" % (operands[0]))
            elif opcode == 0xfb:
                acme_dump_caseblock(opcode, operands)
            else:
                opdef = opdict[opcode]
                operand_types = opdef['operands']
                acme_dump = opdef.get('acme_dump', None)
                #print('SFTODO99 %02X' % (opcode,))
                if acme_dump:
                    # SFTODO: Truly hacky
                    if acme_dump == acme_dump_label:
                        acme_dump(opcode, operands, rld)
                    else:
                        acme_dump(opcode, operands)
                else:
                    if len(operands) == 0:
                        print("\t!BYTE\t$%02X\t\t\t; %s" % (opcode, opdef['opcode']))
                    else:
                        assert len(operands) == 1
                        print("\t!BYTE\t$%02X,%s\t\t\t; %s\t%s" % (opcode, operands[0].acme(), opdef['opcode'], operands[0].human()))
        print("\n".join(tail))


    def dump(self, rld, esd):
        if not self.is_init():
            label = rld.get_bytecode_function_label()
            print(label.name)
        for label in self.labels[0]:
            print(label.name)
        self.disassemble(rld) # SFTODO MASSIVE HACK
        # LabelledBlob.dump(self, rld, esd)


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
# TODO: esd_index is misnamed in the case of these 'ENTRY' flags
for esd_name, esd_flag, esd_index in esd:
    if esd_flag == 0x08: # entry symbol flag, i.e. an exported symbol
        blob_index = esd_index - org - blob_offset
        label = Label('_X')
        blob.label(blob_index, label)
        new_esd.add_entry(esd_name, label)

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
blob.label(init_offset, Label("_INIT", False))

new_module = Module()
# TODO: Should probably support proper [a:b] slice overload instead of having slice() fn
new_module.data_asm_blob = blob.slice(0, subseg_abs - org - blob_offset)

#new_module.bytecode_blob = blob.slice(subseg_abs - org - blob_offset, len(blob))
offsets = bytecode_function_offsets + [init_offset, len(blob)]
for start, end in zip(offsets, offsets[1:]):
    bytecode_function_blob = blob.slice(start, end)
    new_module.bytecode_functions.append(BytecodeFunction(bytecode_function_blob))

del blob
del rld
del esd
del defcnt

# TODO: Should the keys in label_dict be the Label objects themselves rather than their names?
label_dict = {}
new_module.data_asm_blob.update_label_dict(label_dict)
for bytecode_function in new_module.bytecode_functions:
    bytecode_function.update_label_dict(label_dict)
#print('SFTODOQ1 %r', label_dict)

assert new_module.bytecode_functions[-1].is_init()
used_things = set()
new_module.bytecode_functions[-1].update_used_things(used_things)
for external_name, reference in new_esd.entry_dict.items():
    label_dict[reference.name].update_used_things(used_things)
#print('SFTODOXXX %r', used_things)
#print('SFTODOXXX %r', len(used_things))
# We preserve the order of things in the input module; this automatically ensure that
# the data/asm blob comes first and init comes last, and it also avoids gratuitous
# reordering which makes comparig the input and output difficult.
used_things_ordered = [new_module.data_asm_blob] + new_module.bytecode_functions
if False: # SFTODO TEMP - DO WANT THIS, BUT EASIER TO DEBUG WITHOUT IT
    #print('SFTODOXY %r' % len(used_things_ordered),)
    #print('SFTODOXY2 %r' % len(set(used_things_ordered)),)
    used_things_ordered = [x for x in used_things_ordered if x in used_things]

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
if used_things_ordered[0] == new_module.data_asm_blob:
    new_module.data_asm_blob.dump(new_rld, new_esd)
    used_things_ordered.pop(0)
print("_SUBSEG")
#new_module.bytecode_blob.dump(new_rld, new_esd)
# TODO: Recognising _INIT by the fact it comes last is a bit of a hack - though do note we must *emit* it last however we handle this
# TODO: I am assuming there is an INIT function - if you look at cmd.pla, you can see the INIT address in the header can be 0 in which case there is no INIT function. I don't know if the compiler always generates a stub INIT, but if it does we can probably optimise it away if it does nothing but 'RET' or similar.
if False:
    assert new_module.bytecode_functions[-1].is_init()
    #print('SFTODOINITLEN %d' % len(new_module.bytecode_functions[-1].blob))
    for bytecode_function in new_module.bytecode_functions[0:-1]:
        bytecode_function.dump(new_rld, new_esd)
    new_module.bytecode_functions[-1].dump(new_rld, new_esd)
    defcnt = len(new_module.bytecode_functions)
else:
    assert used_things_ordered[-1].is_init()
    for bytecode_function in used_things_ordered[0:-1]:
        bytecode_function.dump(new_rld, new_esd)
    used_things_ordered[-1].dump(new_rld, new_esd)
    defcnt = len(used_things_ordered)

print("_DEFCNT = %d" % (defcnt,))
print("_SEGEND")
print(";\n; RE-LOCATEABLE DICTIONARY\n;")

new_rld.dump()

new_esd.dump()
