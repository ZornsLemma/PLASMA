import abc
import collections
import itertools
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
        #print(repr(label_dict[self.name]))
        label_dict[self.name].update_used_things(used_things)

    def rename_local_labels(self, alias):
        pass

    def update_local_labels_used(self, labels):
        pass

    @classmethod
    def disassemble(cls, di, i):
        label = di.references[i]
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

    def rename_local_labels(self, alias):
        pass

    def update_local_labels_used(self, labels):
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

    def dump(self): # SFTODO: SHOULD PROB TAKE ESD ARG INSTEAD OF USING GLOBAL new_esd
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
        return ord(self.blob[key])

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
        return self[key] | (self[key+1] << 8)

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
        #print("; SFTODO BLOB START %r" % self)
        i = 0
        fixup_count = 0
        while i < len(self.blob):
            if not self.references[i]:
                #print('SFTODO XXX %d %d %d' % (i, len(self.labels), len(self.labels[i])))
                for label in self.labels[i]:
                    print('%s' % label.name)
                print('\t!BYTE\t$%02X' % (self[i],))
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

    def __str__(self):
        return "%d" % (self.value,)

    def __repr__(self):
        return "Byte(%d)" % (self.value,)

    def acme(self):
        return "$%02X" % (self.value,)

    def human(self):
        return "%d" % (self.value,)

    def update_used_things(self, used_things):
        pass

    def rename_local_labels(self, alias):
        pass

    def update_local_labels_used(self, labels):
        pass

    @classmethod
    def disassemble(cls, di, i):
        byte = cls(di.labelled_blob[i])
        return byte, i+1


class FrameOffset(Byte):
    def human(self):
        return "[%d]" % (self.value,)



class Word:
    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return "Word(%d)" % (self.value,)

    def update_used_things(self, used_things):
        pass

    def rename_local_labels(self, alias):
        pass

    def update_local_labels_used(self, labels):
        pass

    @classmethod
    def disassemble(cls, di, i):
        assert False
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

    def update_used_things(self, used_things):
        pass

    def rename_local_labels(self, alias):
        self.value = alias.get(self.value, self.value)

    def update_local_labels_used(self, labels):
        labels.add(self.value)

    @classmethod
    def disassemble(cls, di, i, current_pos = None):
        if not current_pos:
            current_pos = i
        value = di.labelled_blob.read_u16(i)
        value = sign_extend(value, 16)
        target = i + value
        global local_label_count
        local_label = '_L%04d' % (local_label_count,)
        #print("; SFTODO ASSIGNING LOCAL LABEL %s" % (local_label,))
        local_label_count += 1
        if target > current_pos:
            di.local_target[target].append(local_label)
        elif target < current_pos:
            j = 0
            while j < len(di.op_offset):
                if di.op_offset[j] == target:
                    di.op_offset.insert(j, None)
                    di.bytecode_function.ops.insert(j, LocalLabelInstruction(local_label))
                    j = 99999 # SFTODO ULTRA FOUL
                j += 1
            assert j >= 99999
        return Offset(local_label), i+2



class CaseBlockOffset:
    def __init__(self, offset):
        self.offset = offset

    def __repr__(self):
        return "CaseBlockOffset(%r)" % (self.offset,)

    @property
    def value(self): # SFTODO BIT OF A HACKY TO MAKE THIS USABLE WITH acme_dump_branch
        return self.offset.value

    def update_used_things(self, used_things):
        pass

    def rename_local_labels(self, alias):
        self.offset.rename_local_labels(alias)

    def update_local_labels_used(self, labels):
        self.offset.update_local_labels_used(labels)

    @classmethod
    def disassemble(cls, di, i):
        cbo = di.labelled_blob.read_u16(i)
        j = i + cbo
        offset, i = Offset.disassemble(di, i)
        di.special[j] = True # SFTODO HACKY?
        return CaseBlockOffset(offset), i


class CaseBlock:
    def __init__(self, table):
        self.table = table

    def __repr__(self):
        return "CaseBlock(%d)" % (len(self.table),)

    def update_used_things(self, used_things):
        pass

    def rename_local_labels(self, alias):
        for value, offset in self.table:
            offset.rename_local_labels(alias)

    def update_local_labels_used(self, labels):
        for value, offset in self.table:
            offset.update_local_labels_used(labels)

    @classmethod
    def disassemble(cls, di, i):
        count = di.labelled_blob[i]
        table = []
        for j in range(count):
            k = i + 1 + 4*j
            value = di.labelled_blob.read_u16(k)
            offset, _ = Offset.disassemble(di, k+2, i)
            table.append((value, offset))
        return CaseBlock(table), i+1+4*count


class String:
    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return "String(%r)" % (self.value,)

    def update_used_things(self, used_things):
        pass

    def rename_local_labels(self, alias):
        pass

    def update_local_labels_used(self, labels):
        pass

    @classmethod
    def disassemble(cls, di, i):
        length = di.labelled_blob[i]
        s = ''
        for j in range(length):
            s += chr(di.labelled_blob[i + j + 1])
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
    print(1/0) # SFTODO THIS FN NOT USED
    #print("\t!BYTE\t$52\t\t\t; SEL\t%s" % (operands[0].offset.nm(),))
    #print("\t!WORD\t%s-*" % (operands[0].offset.nm(),))
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






class DisassemblyInfo:
    """Collection of temporary information needing while disassembling a bytecode
       function; can be discarded once disassembly is complete."""
    def __init__(self, bytecode_function, labelled_blob):
        self.bytecode_function = bytecode_function
        self.labelled_blob = labelled_blob
        self.references = labelled_blob.references # SFTODO!? IF THIS LIVES, WE CAN ACCESS IT VIA SELF.LABELLED_BLOB
        self.local_target = [[] for _ in range(len(labelled_blob))] # SFTODO VERY EXPERIMENTAL
        self.special = [None] * len(labelled_blob) # SFTODO: COULD USE FALSE? OR JUST HAVE A DICT?
        self.op_offset = []


# TODO: At least temporarily while Instruction objects can be constructed directly during transition, I am not doing things like overriding is_local_label() in the relevant derived class, because it breaks when an Instruction object is constructed
class Instruction(object):
    def __init__(self, opcode, operands):
        assert isinstance(operands, list)
        self._opcode = opcode
        self.operands = operands

    # It may or may not be Pythonic but we use a property here to prevent code accidentally
    # changing the opcode. Doing so would lead to subtle problems because the type of the
    # object wouldn't change.
    @property
    def opcode(self):
        return self._opcode

    def is_local_label(self):
        return self.opcode == 0xff # SFTODO MAGIC CONSTANT

    def is_branch(self):
        return False

    def is_store(self):
        return opdict[self.opcode].get('is_store', False)

    def is_load(self):
        return opdict[self.opcode].get('is_load', False)

    def rename_local_labels(self, alias_dict):
        pass


class ConstantInstruction(Instruction):
    def __init__(self, value):
        assert isinstance(value, int)
        super(ConstantInstruction, self).__init__(0xfd, [value])

    @classmethod
    def disassemble(cls, disassembly_info, i):
        opcode = disassembly_info.labelled_blob[i]
        if opcode <= 0x1e: # CN opcode
            return ConstantInstruction(opcode/2), i+1
        elif opcode == 0x20: # MINUS ONE opcode
            return ConstantInstruction(-1), i+1
        elif opcode == 0x2a: # CB opcode
            return ConstantInstruction(disassembly_info.labelled_blob[i+1]), i+2
        elif opcode == 0x2c: # CW opcode
            return ConstantInstruction(sign_extend(disassembly_info.labelled_blob.read_u16(i+1), 16)), i+3
        elif opcode == 0x5e: # CFFB opcode
            return ConstantInstruction(0xff00 | disassembly_info.labelled_blob[i+1]), i+2
        else:
            print('SFTODO %02x' % opcode)
            assert False

    def dump(self, rld):
        value = self.operands[0]
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

    def rename_local_labels(self, alias_dict):
        pass

class LocalLabelInstruction(Instruction):
    def __init__(self, value):
        assert isinstance(value, str)
        super(LocalLabelInstruction, self).__init__(0xff, [value])

    def dump(self, rld):
        print("%s" % (self.operands[0]))

    def rename_local_labels(self, alias_dict):
        assert self.operands[0] not in alias_dict


class NopInstruction(Instruction):
    def __init__(self):
        super(NopInstruction, self).__init__(0xf1, [])

    def rename_local_labels(self, alias_dict):
        pass


class CaseBlockInstruction(Instruction):
    def __init__(self, value):
        assert isinstance(value, CaseBlock) # SFTODO: 'CaseBlock' MAY EVENTUALLY FOLD INTO THIS, NOT AT ALL SURE YET
        super(CaseBlockInstruction, self).__init__(0xfb, [value])

    def dump(self, rld):
        acme_dump_caseblock(self.opcode, self.operands) # SFTODO FOLD INTO HERE?

    def rename_local_labels(self, alias_dict):
        self.operands[0].rename_local_labels(alias_dict)


class BranchInstruction(Instruction):
    def __init__(self, opcode, target):
        # SFTODO: Magic constants - we should perhaps be consulting opdict here instead
        assert opcode in (0x22, 0x24, 0x4c, 0x4e, 0x50, 0xa0, 0xa2, 0xa4, 0xa8, 0xac, 0xae)
        assert isinstance(target, Offset)
        super(BranchInstruction, self).__init__(opcode, [target])

    @classmethod
    def disassemble(cls, disassembly_info, i):
        opcode = disassembly_info.labelled_blob[i]
        # SFTODO: Validate opcode?? Arguably redundant given how this is called
        offset, i = Offset.disassemble(disassembly_info, i+1)
        return BranchInstruction(opcode, offset), i

    def is_branch(self):
        return True

    def dump(self, rld):
        # SFTODO: Fold acme_dump_branch() in here? Also used in SelInstruction tho...
        acme_dump_branch(self.opcode, self.operands)

    def rename_local_labels(self, alias_dict):
        self.operands[0].rename_local_labels(alias_dict)


class SelInstruction(Instruction):
    def __init__(self, case_block_offset):
        # SFTODO: Perhaps we should not have CaseBlockOffset any more but let's minimise changes for now
        assert isinstance(case_block_offset, CaseBlockOffset)
        super(SelInstruction, self).__init__(0x52, [case_block_offset])

    @classmethod
    def disassemble(cls, disassembly_info, i):
        case_block_offset, i = CaseBlockOffset.disassemble(disassembly_info, i+1)
        return SelInstruction(case_block_offset), i

    def is_branch(self):
        return True

    def dump(self, rld):
        # SFTODO: Fold acme_dump_branch() in here?
        acme_dump_branch(self.opcode, self.operands)

    def rename_local_labels(self, alias_dict):
        self.operands[0].rename_local_labels(alias_dict)



# SFTODO: Not sure about this, but let's see how it goes
# SFTODO: Perhaps rename this ImpliedInstruction? I use it for things like RET which don't really use the stack as such, but are similar in the sense that the data (if any) is implied, not explicit.
class StackInstruction(Instruction):
    def __init__(self, opcode):
        # SFTODO: WE SHOULD PROBABLY ASSERT - MAYBE USING opdict - THAT THIS IS A STACK INSTRUCTION
        super(StackInstruction, self).__init__(opcode, [])

    @classmethod
    def disassemble(cls, disassembly_info, i):
        opcode = disassembly_info.labelled_blob[i]
        # SFTODO: Validate opcode?? Arguably redundant given how this is called
        return StackInstruction(opcode), i+1

    def dump(self, rld):
        print("\t!BYTE\t$%02X\t\t\t; %s" % (self.opcode, opdict[self.opcode]['opcode']))

    def rename_local_labels(self, alias_dict):
        pass


class ImmediateInstruction(Instruction):
    def __init__(self, opcode, operands):
        assert isinstance(operands, list)
        assert len(operands) > 0
        # SFTODO: We may or may not want to retain the Byte type rather than using raw ints eventually but let's keep it for now to minimise changes
        assert all(isinstance(x, Byte) for x in operands)
        super(ImmediateInstruction, self).__init__(opcode, operands)

    @classmethod
    def disassemble(cls, disassembly_info, i, operand_count):
        opcode = disassembly_info.labelled_blob[i]
        # SFTODO: Validate opcode?? Arguably redundant given how this is called
        i += 1
        operands = []
        for j in range(operand_count):
            operand, i = Byte.disassemble(disassembly_info, i)
            operands.append(operand)
        return ImmediateInstruction(opcode, operands), i

    @classmethod
    def disassemble1(cls, disassembly_info, i):
        return cls.disassemble(disassembly_info, i, 1)

    @classmethod
    def disassemble2(cls, disassembly_info, i):
        return cls.disassemble(disassembly_info, i, 2)

    def dump(self, rld):
        if len(self.operands) == 1:
            print("\t!BYTE\t$%02X,$%02X\t\t\t; %s\t%s" % (self.opcode, self.operands[0].value, opdict[self.opcode]['opcode'], self.operands[0].value))
        elif len(self.operands) == 2:
            print("\t!BYTE\t$%02X,$%02X,$%02X\t\t; %s\t%s,%s" % (self.opcode, self.operands[0].value, self.operands[1].value, opdict[self.opcode]['opcode'], self.operands[0].value, self.operands[1].value))
        else:
            assert False

    def rename_local_labels(self, alias_dict):
        pass


class MemoryInstruction(Instruction):
    def __init__(self, opcode, address):
        # TODO: For the moment we just assume the only kind of address is a label; need to make this work with absolute addresses as well.
        assert isinstance(address, Label) or isinstance(address, ExternalReference)
        super(MemoryInstruction, self).__init__(opcode, [address])

    @classmethod
    def disassemble(cls, disassembly_info, i):
        opcode = disassembly_info.labelled_blob[i]
        # SFTODO: Validate opcode?? Arguably redundant given how this is called
        i += 1
        label, i = Label.disassemble(disassembly_info, i)
        return MemoryInstruction(opcode, label), i

    def dump(self, rld):
        # SFTODO: Probably merge acme_dump_label in here
        acme_dump_label(self.opcode, self.operands, rld)

    def rename_local_labels(self, alias_dict):
        pass


# SFTODO: Not sure about this, but let's see how it goes
class FrameInstruction(Instruction):
    def __init__(self, opcode, frame_offset):
        # SFTODO: WE SHOULD PROBABLY ASSERT - MAYBE USING opdict - THAT THIS IS A FRAME INSTRUCTION
        assert isinstance(frame_offset, FrameOffset)
        super(FrameInstruction, self).__init__(opcode, [frame_offset])

    @property
    def frame_offset(self):
        return self.operands[0].value

    @classmethod
    def disassemble(cls, disassembly_info, i):
        opcode = disassembly_info.labelled_blob[i]
        # TODO: I think FrameOffset probably adds very little and we should just use a raw int here, but let's not try to get rid of it just yet
        frame_offset = FrameOffset(disassembly_info.labelled_blob[i+1])
        return FrameInstruction(opcode, frame_offset), i+2

    def dump(self, rld):
        print("\t!BYTE\t$%02X,$%02X\t\t\t; %s\t[%s]" % (self.opcode, self.operands[0].value, opdict[self.opcode]['opcode'], self.operands[0].value))

    def rename_local_labels(self, alias_dict):
        pass


class StringInstruction(Instruction):
    def __init__(self, s):
        # SFTODO: NOT SURE IF WE WANT TO RETAIN THE 'String' CLASS OR FOLD IT IN HERE, BUT LET'S KEEP IT MINIMAL CHANGE FOR NOW
        assert isinstance(s, String)
        super(StringInstruction, self).__init__(0x2e, [s])

    @classmethod
    def disassemble(cls, disassembly_info, i):
        s, i = String.disassemble(disassembly_info, i+1)
        return StringInstruction(s), i

    def dump(self, rld):
        # SFTODO: Fold acme_dump_cs in here
        acme_dump_cs(self.opcode, self.operands)

    def rename_local_labels(self, alias_dict):
        pass



# TODO: Possibly the disassembly should turn CN into CB or just a 'CONST' pseudo-opcode (which CW/CFFB/MINUSONE would also turn into) and then when we emit bytecode from the disassembly we'd use the optimal one - I have done this, but it many ways it would be cleaner to turn them all into CW not a CONST pseudo-op, and then optimise CW on output instead of optimising this CONST pseudo-op
# TODO: We may well want to have a class FrameOffset deriving from Byte and use that for some operands - this would perhaps do nothing more than use the [n] representation in the comments on assembler output, but might be a nice way to get that for little extra effort
# TODO: Check this table is complete and correct
# TODO: I do wonder if we'd go wrong if we actually had something like '*$3000=42' in a PLASMA program; we seem to be assuming that the operand of some opcodes is always a label, when it *might* be a literal
# TODO: I suspect I won't want most of the things in here eventually, but for now I am avoiding removing anything and just adding stuff. Review this later and get rid of unwanted stuff.
opdict = {
    0x00: {'opcode': 'CN', 'dis': ConstantInstruction.disassemble},
    0x02: {'opcode': 'CN', 'dis': ConstantInstruction.disassemble},
    0x04: {'opcode': 'CN', 'dis': ConstantInstruction.disassemble},
    0x06: {'opcode': 'CN', 'dis': ConstantInstruction.disassemble},
    0x08: {'opcode': 'CN', 'dis': ConstantInstruction.disassemble},
    0x0a: {'opcode': 'CN', 'dis': ConstantInstruction.disassemble},
    0x0c: {'opcode': 'CN', 'dis': ConstantInstruction.disassemble},
    0x0e: {'opcode': 'CN', 'dis': ConstantInstruction.disassemble},
    0x10: {'opcode': 'CN', 'dis': ConstantInstruction.disassemble},
    0x12: {'opcode': 'CN', 'dis': ConstantInstruction.disassemble},
    0x14: {'opcode': 'CN', 'dis': ConstantInstruction.disassemble},
    0x16: {'opcode': 'CN', 'dis': ConstantInstruction.disassemble},
    0x18: {'opcode': 'CN', 'dis': ConstantInstruction.disassemble},
    0x1a: {'opcode': 'CN', 'dis': ConstantInstruction.disassemble},
    0x1c: {'opcode': 'CN', 'dis': ConstantInstruction.disassemble},
    0x1e: {'opcode': 'CN', 'dis': ConstantInstruction.disassemble},
    0x20: {'opcode': 'MINUS1', 'dis': ConstantInstruction.disassemble},
    0x22: {'opcode': 'BREQ', 'dis': BranchInstruction.disassemble},
    0x24: {'opcode': 'BRNE', 'dis': BranchInstruction.disassemble},
    0x26: {'opcode': 'LA', 'dis': MemoryInstruction.disassemble},
    0x28: {'opcode': 'LLA', 'dis': FrameInstruction.disassemble},
    0x2a: {'opcode': 'CB', 'dis': ConstantInstruction.disassemble},
    0x2c: {'opcode': 'CW', 'dis': ConstantInstruction.disassemble},
    0x2e: {'opcode': 'CS', 'dis': StringInstruction.disassemble},
    0x30: {'opcode': 'DROP', 'dis': StackInstruction.disassemble},
    0x34: {'opcode': 'DUP', 'dis': StackInstruction.disassemble},
    0x38: {'opcode': 'ADDI', 'dis': ImmediateInstruction.disassemble1},
    0x3a: {'opcode': 'SUBI', 'dis': ImmediateInstruction.disassemble1},
    0x3c: {'opcode': 'ANDI', 'dis': ImmediateInstruction.disassemble1},
    0x3e: {'opcode': 'ORI', 'dis': ImmediateInstruction.disassemble1},
    0x40: {'opcode': 'ISEQ', 'dis': StackInstruction.disassemble},
    0x42: {'opcode': 'ISNE', 'dis': StackInstruction.disassemble},
    0x44: {'opcode': 'ISGT', 'dis': StackInstruction.disassemble},
    0x46: {'opcode': 'ISLT', 'dis': StackInstruction.disassemble},
    0x48: {'opcode': 'ISGE', 'dis': StackInstruction.disassemble},
    0x4a: {'opcode': 'ISLE', 'dis': StackInstruction.disassemble},
    0x4c: {'opcode': 'BRFLS', 'dis': BranchInstruction.disassemble},
    0x4e: {'opcode': 'BRTRU', 'dis': BranchInstruction.disassemble},
    0x50: {'opcode': 'BRNCH', 'dis': BranchInstruction.disassemble, 'nis': True},
    0x52: {'opcode': 'SEL', 'dis': SelInstruction.disassemble}, # SFTODO: THIS IS GOING TO NEED MORE CARE, BECAUSE THE OPERAND IDENTIFIES A JUMP TABLE WHICH WE WILL NEED TO HANDLE CORRECTLY WHEN DISASSEMBLY REACHES IT
    0x54: {'opcode': 'CALL', 'dis': MemoryInstruction.disassemble}, # SFTODO: MemoryInstruction isn't necessarily best class here, but let's try it for now
    0x56: {'opcode': 'ICAL', 'dis': StackInstruction.disassemble},
    0x58: {'opcode': 'ENTER', 'dis': ImmediateInstruction.disassemble2},
    0x5c: {'opcode': 'RET', 'nis': True, 'dis': StackInstruction.disassemble},
    0x5a: {'opcode': 'LEAVE', 'nis': True, 'dis': ImmediateInstruction.disassemble1},
    0x5e: {'opcode': 'CFFB', 'dis': ConstantInstruction.disassemble},
    0x60: {'opcode': 'LB', 'dis': StackInstruction.disassemble},
    0x62: {'opcode': 'LW', 'dis': StackInstruction.disassemble},
    0x64: {'opcode': 'LLB', 'is_load': True, 'data_size': 1, 'dis': FrameInstruction.disassemble},
    0x66: {'opcode': 'LLW', 'is_load': True, 'data_size': 2, 'dis': FrameInstruction.disassemble},
    0x68: {'opcode': 'LAB', 'dis': MemoryInstruction.disassemble},
    0x6c: {'opcode': 'DLB', 'is_load': True, 'is_store': True, 'data_size': 1, 'dis': FrameInstruction.disassemble},
    0x6e: {'opcode': 'DLW', 'is_load': True, 'is_store': True, 'data_size': 2, 'dis': FrameInstruction.disassemble},
    0x6a: {'opcode': 'LAW', 'dis': MemoryInstruction.disassemble},
    0x70: {'opcode': 'SB', 'dis': StackInstruction.disassemble},
    0x72: {'opcode': 'SW', 'dis': StackInstruction.disassemble},
    0x74: {'opcode': 'SLB', 'is_store': True, 'data_size': 1, 'dis': FrameInstruction.disassemble},
    0x76: {'opcode': 'SLW', 'is_store': True, 'data_size': 2, 'dis': FrameInstruction.disassemble},
    0x78: {'opcode': 'SAB', 'dis': MemoryInstruction.disassemble},
    0x7a: {'opcode': 'SAW', 'dis': MemoryInstruction.disassemble},
    0x7c: {'opcode': 'DAB', 'dis': MemoryInstruction.disassemble},
    0x7e: {'opcode': 'DAW', 'dis': MemoryInstruction.disassemble},
    0x80: {'opcode': 'LNOT', 'dis': StackInstruction.disassemble},
    0x82: {'opcode': 'ADD', 'dis': StackInstruction.disassemble},
    0x84: {'opcode': 'SUB', 'dis': StackInstruction.disassemble},
    0x86: {'opcode': 'MUL', 'dis': StackInstruction.disassemble},
    0x88: {'opcode': 'DIV', 'dis': StackInstruction.disassemble},
    0x8a: {'opcode': 'MOD', 'dis': StackInstruction.disassemble},
    0x8c: {'opcode': 'INCR', 'dis': StackInstruction.disassemble},
    0x8e: {'opcode': 'DECR', 'dis': StackInstruction.disassemble},
    0x90: {'opcode': 'NEG', 'dis': StackInstruction.disassemble},
    0x92: {'opcode': 'COMP', 'dis': StackInstruction.disassemble},
    0x94: {'opcode': 'BAND', 'dis': StackInstruction.disassemble},
    0x96: {'opcode': 'IOR', 'dis': StackInstruction.disassemble},
    0x98: {'opcode': 'XOR', 'dis': StackInstruction.disassemble},
    0x9a: {'opcode': 'SHL', 'dis': StackInstruction.disassemble},
    0x9c: {'opcode': 'SHR', 'dis': StackInstruction.disassemble},
    0x9e: {'opcode': 'IDXW', 'dis': StackInstruction.disassemble},
    0xa0: {'opcode': 'BRGT', 'dis': BranchInstruction.disassemble},
    0xa2: {'opcode': 'BRLT', 'dis': BranchInstruction.disassemble},
    0xa4: {'opcode': 'INCBRLE', 'dis': BranchInstruction.disassemble},
    0xa8: {'opcode': 'DECBRGE', 'dis': BranchInstruction.disassemble},
    0xac: {'opcode': 'BRAND', 'dis': BranchInstruction.disassemble},
    0xae: {'opcode': 'BROR', 'dis': BranchInstruction.disassemble},
    0xb0: {'opcode': 'ADDLB', 'is_load': True, 'data_size': 1, 'dis': FrameInstruction.disassemble},
    0xb2: {'opcode': 'ADDLW', 'is_load': True, 'data_size': 2, 'dis': FrameInstruction.disassemble},
    0xb4: {'opcode': 'ADDAB', 'dis': MemoryInstruction.disassemble},
    0xb6: {'opcode': 'ADDAW', 'dis': MemoryInstruction.disassemble},
    0xb8: {'opcode': 'IDXLB', 'is_load': True, 'data_size': 1, 'dis': FrameInstruction.disassemble},
    0xba: {'opcode': 'IDXLW', 'is_load': True, 'data_size': 2, 'dis': FrameInstruction.disassemble},
    0xbc: {'opcode': 'IDXAB', 'dis': MemoryInstruction.disassemble},
    0xbe: {'opcode': 'IDXAW', 'dis': MemoryInstruction.disassemble},
}

class BytecodeFunction:
    def __init__(self, labelled_blob):
        assert isinstance(labelled_blob, LabelledBlob)
        self.labels = labelled_blob.labels[0]
        self.ops = [] # SFTODO Should perhaps call 'instructions'
        di = DisassemblyInfo(self, labelled_blob)

        i = 0
        while i < len(labelled_blob):
            # There should be no labels within a bytecode function. We will later
            # create branch-target labels based on the branch instructions within
            # the function, but those are different.
            assert i == 0 or not labelled_blob.labels[i]
            for t in di.local_target[i]:
                self.ops.append(LocalLabelInstruction(t))
                di.op_offset.append(None)
            di.op_offset.append(i) # SFTODO SHOULD WE DO THIS EVEN IF SPECIAL?
            special = di.special[i]
            if not special:
                opcode = labelled_blob[i]
                #print('SFTODOQQ %X' % opcode)
                opdef = opdict[opcode]
                dis = opdef.get('dis')
                op, i = dis(di, i)
            else:
                operand, i = CaseBlock.disassemble(di, i)
                op = CaseBlockInstruction(operand)
            self.ops.append(op)

    def is_init(self):
        return any(x.name == '_INIT' for x in self.labels)



    def update_label_dict(self, label_dict):
        for label in self.labels:
            label_dict[label.name] = self

    def update_used_things(self, used_things):
        if self in used_things:
            return
        used_things.add(self)
        #print("SFTODO99 %r %r" % (self, len(self.references)))
        #print("SFTODO99 %r" % self.references)
        for instruction in self.ops:
            assert isinstance(instruction, Instruction) # SFTODO TEMP DURING TRANSITION
            for operand in instruction.operands:
                if not isinstance(operand, int) and not isinstance(operand, str): # SFTODO: HACKY
                    operand.update_used_things(used_things)

    def dump(self, rld, esd): # SFTODO: We don't use the esd arg
        if not self.is_init():
            label = rld.get_bytecode_function_label()
            print(label.name)
        for label in self.labels:
            print(label.name)
        for instruction in self.ops:
            instruction.dump(rld)

# Remove all but the first of each group of consecutive labels; this makes it easier to spot other
# optimisations.
def local_label_deduplicate(bytecode_function):
    alias = {}
    new_ops = []
    previous_instruction = None
    changed = False
    for instruction in bytecode_function.ops:
        if instruction.is_local_label() and previous_instruction and previous_instruction.is_local_label():
            alias[instruction.operands[0]] = previous_instruction.operands[0]
            changed = True
        else:
            previous_instruction = instruction
            new_ops.append(instruction)
    for instruction in new_ops:
        instruction.rename_local_labels(alias)
    bytecode_function.ops = new_ops
    return changed


def branch_optimise(bytecode_function):
    # This relies on local_label_deduplicate() being called beforehand
    changed = False
    # This removes a BRNCH to an immediately following label.
    # TODO: There are probably other opportunities for optimisation here but this is a
    # simple case which seems to occur a bit. (We remove a BRNCH to an immedatiately
    # following label.)
    # TODO: I don't think it occurs much, but potentially we could replace BRTRU or BRFLS
    # to an immediately following label with a DROP.
    new_ops = []
    for i in range(len(bytecode_function.ops)):
        instruction = bytecode_function.ops[i]
        next_instruction = None if i == len(bytecode_function.ops)-1 else bytecode_function.ops[i+1]
        if not (instruction.opcode == 0x50 and next_instruction and next_instruction.is_local_label() and instruction.operands[0].value == next_instruction.operands[0]): # SFTODO MAGIC CONST
            new_ops.append(instruction)
        else:
            changed = True
        # TODO: When we remove the branch we leave the label it brancehd too - we don't have a simple way to determine if anyone else is using it. It probably makes no difference, but it may turn out to be useful to remove orphaned labels to open up further optimisation possibilities.
    bytecode_function.ops = new_ops
    return changed



# This replaces a BRNCH to a LEAVE or RET with the LEAVE or RET itself.
def branch_optimise2(bytecode_function):
    # This relies on local_label_deduplicate() being called beforehand
    changed = False
    targets = {}
    for i in range(len(bytecode_function.ops)-1):
        if bytecode_function.ops[i].is_local_label() and bytecode_function.ops[i+1].opcode in (0x5a, 0x5c): # SFTODO: MAGIC CONST RET LEAVE
            targets[bytecode_function.ops[i].operands[0]] = bytecode_function.ops[i+1]
    #print('SFTODOQ4', targets)
    for i in range(len(bytecode_function.ops)):
        if bytecode_function.ops[i].opcode == 0x50: # SFTODO MAGIC
            local_label = bytecode_function.ops[i].operands[0].value
            #print('SFTODOQ5', local_label)
            if local_label in targets:
                bytecode_function.ops[i] = targets[local_label]
                changed = True
    # TODO: We will leave a potentially orphaned label from removed branches here. This might inhibit some other optimisations (e.g. removal of redundant stores - hitting a LEAVE or RET is gold, but the preceding label will break the straight line sequence). Need to come back to this - we need to be calling optimisations in a sensible order (looping over at least some of them multiple times) until we find no more improvements.
    return changed

# This replaces a branch (conditional or not) to a BRNCH with a branch.
# TODO: This would definitely benefit from being called in a loop; we can get branch-to-branch-to-branch occasionally and it won't snap all the way to the final destination on a single pass.
# TODO: Not just relevant to this, but this probably is one cause - we might benefit from removing orphaned labels and then removing dead code - for example, this optimisation may cause a branch instruction to be redundant because it was only ever used as a target for other branches which have been snapped
# TODO: This should also treat CASEBLOCK targets as BRNCH opcodes - which they kind of are. There is at least one case in self-hosted compiled where such a target could be snapped, and it may also then allow the intermediate branch (which follows another unconditional branch) to be removed by the dead code optimisation.
def branch_optimise3(bytecode_function):
    # This relies on local_label_deduplicate() being called beforehand
    changed = False
    targets = {}
    for i in range(len(bytecode_function.ops)-1):
        if bytecode_function.ops[i].is_local_label() and bytecode_function.ops[i+1].opcode == 0x50: # SFTODO MAGIC BRNCH
            targets[bytecode_function.ops[i].operands[0]] = bytecode_function.ops[i+1]
    #print('SFTODOQ4', targets)
    for i in range(len(bytecode_function.ops)):
        instruction = bytecode_function.ops[i]
        if instruction.is_branch():
            local_label = bytecode_function.ops[i].operands[0].value
            if local_label in targets:
                bytecode_function.ops[i] = BranchInstruction(instruction.opcode, targets[local_label].operands[0])
                changed = True
    # TODO: As always we may have left a now-orphaned label around
    return changed

def remove_orphaned_labels(bytecode_function):
    changed = False
    labels_used = set()
    for instruction in bytecode_function.ops:
        if instruction.operands and not isinstance(instruction.operands[0], int) and not isinstance(instruction.operands[0], str): # SFTODO HACKY isinstance
            instruction.operands[0].update_local_labels_used(labels_used)
    new_ops = []
    for instruction in bytecode_function.ops:
        if not (instruction.is_local_label() and instruction.operands[0] not in labels_used):
            new_ops.append(instruction)
        else:
            changed = True
    bytecode_function.ops = new_ops
    return changed

def never_immediate_successor(opcode):
    opdef = opdict.get(opcode, None)
    return opdef and opdef.get('nis', False)

def remove_dead_code(bytecode_function):
    # This relies on remove_orphaned_labels() being called beforehand
    changed = False
    new_ops = []
    i = 0
    while i < len(bytecode_function.ops):
        new_ops.append(bytecode_function.ops[i])
        this_opcode = bytecode_function.ops[i].opcode
        i += 1
        if never_immediate_successor(this_opcode):
            while i < len(bytecode_function.ops) and not bytecode_function.ops[i].is_local_label():
                i += 1
                changed = True
    bytecode_function.ops = new_ops
    return changed





def is_branch_or_label(instruction):
    # TODO: THIS MAY NEED TO BE CONFIGURABLE TO DECIDE WHETHER CALL OR ICAL COUNT AS BRANCHES - TBH straightline_optimise() MAY BE BETTER RECAST AS A UTILITY TO BE CALLED BY AN OPTIMISATION FUNCTION NOT SOMETHIG WHICH CALLS OPTIMISATION FUNCTIONS
    return instruction.is_local_label() or instruction.is_branch()

def straightline_optimise(bytecode_function, optimisations):
    changed = False
    groups = []
    group = []
    for instruction in bytecode_function.ops:
        if not group or is_branch_or_label(instruction) == is_branch_or_label(group[-1]):
            group.append(instruction)
        else:
            groups.append(group)
            group = [instruction]
    if group:
        groups.append(group)
    new_ops = []
    for group in groups:
        if not group[0].is_local_label():
            for optimisation in optimisations:
                # optimisation function may modify group in place if it wishes, but it
                # may also be more convenient for it to create a new list so we take a
                # return value; it can of course just 'return group' if it does everything
                # in place.
                group, changed2 = optimisation(bytecode_function, group)
                changed = changed or changed2
        new_ops.extend(group)
    bytecode_function.ops = new_ops
    return changed

def optimise_load_store(bytecode_function, straightline_ops):
    changed = False
    lla_threshold = 256
    for instruction in bytecode_function.ops:
        if instruction.opcode == 0x28: # SFTODO MAGIC CONSTANT 'LLA'
            lla_threshold = min(instruction.operands[0].value, lla_threshold)

    store_index_visibly_affected_bytes = [None] * 256
    last_store_index_for_offset = [None] * 256

    def record_store(this_store_index, frame_offsets):
        for frame_offset in frame_offsets:
            last_store_index = last_store_index_for_offset[frame_offset]
            if last_store_index and store_index_visibly_affected_bytes[last_store_index] > 0:
                store_index_visibly_affected_bytes[last_store_index] -= 1
                if store_index_visibly_affected_bytes[last_store_index] == 0:
                    # The stores performed by straightline_ops[last_store_index] are all
                    # irrelevant, so we don't need to perform them.
                    store_instruction = straightline_ops[last_store_index]
                    assert store_instruction.is_store()
                    if store_instruction.is_load(): # it's a duplicate opcode
                        straightline_ops[last_store_index] = NopInstruction()
                    else:
                        straightline_ops[last_store_index] = StackInstruction(0x30) # SFTODO MAGIC CONSTANT DROP
                    changed = True
            last_store_index_for_offset[frame_offset] = this_store_index
        store_index_visibly_affected_bytes[this_store_index] = len(frame_offsets)

    def record_load(frame_offsets):
        for frame_offset in frame_offsets:
            last_store_index = last_store_index_for_offset[frame_offset]
            if last_store_index:
                store_index_visibly_affected_bytes[last_store_index] = None

    for i in range(len(straightline_ops)):
        instruction = straightline_ops[i]
        opcode, operands = instruction.opcode, instruction.operands
        opdef = opdict.get(opcode, None)
        if opdef:
            is_store = opdef.get('is_store', False)
            is_load = opdef.get('is_load', False)
            is_call = (opcode in (0x54, 0x56)) # SFTODO MAGIC CONSTANTS
            is_exit = (opcode in (0x5a, 0x5c)) # SFTODO MAGIC CONSTANTS
            if is_store or is_load:
                # SFTODO: This assertion may well not be valid later on - at the moment only frame instructions are annotated as loads/stores, but I could well imagine annotating things like LAW with is_load. This code may or may not want to consider optimising such stores, but we will need to think about it.
                assert isinstance(instruction, FrameInstruction)
                frame_offsets = [instruction.frame_offset]
                if opdef.get('data_size') == 2:
                    #print(operands[0])
                    frame_offsets.append(instruction.frame_offset + 1)
            if is_store: # stores and duplicates
                record_store(i, frame_offsets)
            elif is_load: # load, but not a duplicate
                record_load(frame_offsets)
            elif is_call:
                # A function call has to be assumed to load from any frame offsets which
                # have been made available via LLA. We assume it's not valid to use a
                # negative index with the address of a local variable to access another
                # local variable. If, for example, we see an LLA [4] but no other LLA,
                # a function call might load via a pointer from offset 4 or 100, but not
                # offset 3.
                record_load(range(lla_threshold, 256))
            elif is_exit:
                # We're exiting the current function, so anything which has been stored
                # but not yet loaded is irrelevant. We model this by storing to every
                # frame offset.
                record_store(i, range(0, 256))

    return [op for op in straightline_ops if op.opcode != 0xf1], changed


class Module:
    def __init__(self):
        self.sysflags = 0 # SFTODO!?
        self.data_asm_blob = None # SFTODO!?
        self.bytecode_functions = []

input_file = '../rel/PLASM#FE1000' if len(sys.argv) < 2 else sys.argv[1]
with open(input_file, 'rb') as f:
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
if True: # SFTODO: SHOULD BE A COMMAND LINE OPTION, I THINK
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
assert used_things_ordered[-1].is_init()
for bytecode_function in used_things_ordered[0:-1]:
    # TODO: The order here has not been thought through at all carefully and may be sub-optimal
    changed = True
    while changed:
        # TODO: This seems a clunky way to handle 'changed' but I don't want
        # short-circuit evaluation.
        result = []
        if True: # SFTODO TEMP
            result.append(local_label_deduplicate(bytecode_function))
            result.append(branch_optimise(bytecode_function))
            result.append(branch_optimise2(bytecode_function))
            result.append(branch_optimise3(bytecode_function))
            result.append(remove_orphaned_labels(bytecode_function))
            result.append(remove_dead_code(bytecode_function))
            result.append(straightline_optimise(bytecode_function, [optimise_load_store]))
        changed = any(result)
    bytecode_function.dump(new_rld, new_esd)
used_things_ordered[-1].dump(new_rld, new_esd)
defcnt = len(used_things_ordered)

print("_DEFCNT = %d" % (defcnt,))
print("_SEGEND")
print(";\n; RE-LOCATEABLE DICTIONARY\n;")

new_rld.dump()

new_esd.dump()

# TODO: Would it be worth replacing "CN 1:SHL" with "DUP:ADD"? This occurs in the self-hosted compiler at least once. It's the same length, so would need to cycle count to see if it's faster.

# TODO: "LLW [n]:SAW x:LLW [n]" -> "LLW [n]:DAW x"? Occurs at least once in self-hosted compiler.

# TODO: A few times in self-hosted compiler, we have DROP:DROP - we should change this to DROP2.

# TODO: Possibly difficult (and what I am about to write may not be maximally generic) - if all uses of a label are as unconditional branch targets (probably easiest to ignore caseblock here; use in a caseblock would disable this optimisation, unless we work back to its SEL and see the preceding opcode) and every use such plus any possible fallthrough to the label from previous instruction are the same opcode (the case I spotted in SHC is a DROP), we can remove it from before every branch and move the label before it. We could consider only a single opcode at a time, if there are further opportunities a subsequent loop round would catch these.

# TODO: Perhaps not worth it, and this is a space-not-speed optimisation, but if it's common to CALL a function FOO and then immediately do a DROP afterwards (across all code in the module, not just one function), it may be a space-saving win to generate a function FOO-PRIME which does "(no ENTER):CALL FOO:DROP:RET" and replace CALL FOO:DROP with CALL FOO-PRIME. We could potentially generalise this (we couldn't do it over multiple passes) to recognising the longest common sequence of operations occurring after all CALLs to FOO and factoring them all into FOO-PRIME.
