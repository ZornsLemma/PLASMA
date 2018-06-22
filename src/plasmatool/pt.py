import abc
import collections
import copy # SFTODO TEMP
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

class Label(object):
    __next = collections.defaultdict(int)

    def __init__(self, prefix, add_suffix = True):
        if add_suffix:
            i = Label.__next[prefix]
            self.name = '%s%04d' % (prefix, i)
            Label.__next[prefix] += 1
        else:
            self.name = prefix

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.name == other.name
        else:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self.name)

    def __add__(self, rhs):
        # SFTODO: This is a bit odd. We need this for add_affect(). However, I *think* that
        # since we evidently have no need to support the concept of "label+n" anywhere,
        # we can get away with just returning self here - because if it's impossible to
        # represent the concept of "label+1", there is no scope for one bit of code to e.g.
        # LAW label and another bit of code to SAB label+1 and the two to "clash".
        return self

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

class ExternalReference(object):
    def __init__(self, external_name, offset):
        self.external_name = external_name
        self.offset = offset

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.external_name == other.external_name and self.offset == other.offset
        else:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)
        
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

class RLD(object):
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


class ESD(object):
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

class LabelledBlob(object):
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


class Opcode(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def length(self):
        pass
    

class Byte(object):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return "%d" % (self.value,)

    def __repr__(self):
        return "Byte(%d)" % (self.value,)

    def __hash__(self):
        return hash(self.value)

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.value == other.value
        else:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)

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



class Word(object):
    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return "Word(%d)" % (self.value,)

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.value == other.value
        else:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)

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

# SFTODO: Experimental - this can't be a member of Offset because now Offset is used
# for both local label instructions and branch instruction operands, the (unavoidable,
# given how I want to write the code) copying of operands between instructions means
# that local labels and branches end up sharing a single Offset object. We therefore
# must not mutate an Offset object as it affects everything holding a reference to it;
# we must replace the Offset object we're interested in with another one with the
# relevant change. This has been hacked in to test this change, and it does seem to
# work, but it's pretty messy the way some objects *do* have rename_local_labels() as
# a member but we have to remember to use this in some places.
def rename_local_labels(offset, alias):
    assert isinstance(offset, Offset)
    if not alias:
        return offset
    # SFTODO: This is foul but I'm just trying to get things working as part of refactoring
    # and then I can decide how best to handle this properly.
    string_case1 = all(isinstance(k, str) for k,v in alias.items())
    string_case2 = all(isinstance(v, str) for k,v in alias.items())
    offset_case1 = all(isinstance(k, Offset) for k,v in alias.items())
    offset_case2 = all(isinstance(v, Offset) for k,v in alias.items())
    #print string_case1, string_case2, offset_case1, offset_case2
    assert not string_case1 and not string_case2 and offset_case1 and offset_case2
    return Offset(alias.get(offset, offset)._value)


# SFTODO: I think I want to rename this LocalLabel, but let's not worry about that just yet.
class Offset(object):
    def __init__(self, value):
        assert isinstance(value, str)
        self._value = value

    def __str__(self):
        return self._value

    def __repr__(self):
        return "Offset(%s)" % (self._value,)

    def __hash__(self):
        return hash(self._value)

    def __eq__(self, other):
        assert isinstance(self._value, str) # SFTODO TEMP
        if isinstance(other, self.__class__):
            return self._value == other._value
        else:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def update_used_things(self, used_things):
        pass

    def rename_local_labels(self, alias):
        assert False # SFTODO: THIS IS WRONG/DANGEROUS - SEE COMMENT ON rename_local_labels ABOVE

    def update_local_labels_used(self, labels):
        # SFTODO: Should this add self._value? I am still trying to figure it out but for the
        # moment I want to un-break things
        labels.add(self)

    @classmethod
    def disassemble(cls, di, i, current_pos = None):
        if not current_pos:
            current_pos = i
        value = di.labelled_blob.read_u16(i)
        value = sign_extend(value, 16)
        target = i + value
        global local_label_count
        local_label = Offset('_L%04d' % (local_label_count,))
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
        return local_label, i+2



class CaseBlockOffset(object):
    def __init__(self, offset):
        self.offset = offset

    def __repr__(self):
        return "CaseBlockOffset(%r)" % (self.offset,)

    def __str__(self):
        return str(self.offset)

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.offset == other.offset
        else:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)

    @property
    def value(self): # SFTODO BIT OF A HACKY TO MAKE THIS USABLE WITH acme_dump_branch
        return self.offset.value

    def update_used_things(self, used_things):
        pass

    def rename_local_labels(self, alias):
        self.offset = rename_local_labels(self.offset, alias)

    def update_local_labels_used(self, labels):
        self.offset.update_local_labels_used(labels)

    @classmethod
    def disassemble(cls, di, i):
        cbo = di.labelled_blob.read_u16(i)
        j = i + cbo
        offset, i = Offset.disassemble(di, i)
        di.special[j] = True # SFTODO HACKY?
        return CaseBlockOffset(offset), i


class CaseBlock(object):
    def __init__(self, table):
        self.table = table

    def __repr__(self):
        return "CaseBlock(%d)" % (len(self.table),)

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.table == other.table
        else:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def update_used_things(self, used_things):
        pass

    def rename_local_labels(self, alias):
        for i, (value, offset) in enumerate(self.table):
            self.table[i] = (self.table[i][0], rename_local_labels(self.table[i][1], alias))

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


class String(object):
    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return "String(%r)" % (self.value,)

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.value == other.value
        else:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)

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
    print("\t!BYTE\t$%02X\t\t\t; %s\t%s" % (opcode, opdict[opcode]['opcode'], operands[0]))
    print("\t!WORD\t%s-*" % (operands[0],))

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
        print("\t!WORD\t%s-*" % (offset,))






class DisassemblyInfo(object):
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

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self._opcode == other._opcode and self.operands == other.operands
        else:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)

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

    def is_conditional_branch(self):
        return False

    def is_store(self):
        if self.opcode % 2 == 1: # SFTODO: BIT OF A HACK
            return False
        return opdict[self.opcode].get('is_store', False)

    def is_simple_store(self):
        # TODO: This is a bit of a hack but let's see how it goes
        return self.is_store() and self.opcode not in (0x70, 0x72) # SFTODO MAGIC SB, SW

    def is_load(self):
        if self.opcode % 2 == 1: # SFTODO: BIT OF A HACK
            return False
        return opdict[self.opcode].get('is_load', False)

    def is_simple_load(self):
        # TODO: This is a bit of a hack but let's see how it goes
        return self.is_load() and self.opcode not in (0x60, 0x62, 0xb0, 0xb2, 0xb4, 0xb6, 0xb8, 0xba, 0xbc, 0xbe)

    def has_side_effects(self):
        # SFTODO: Once I actually start supporting loads/stores to absolute addresses,
        # this needs to return True for those just as is_hardware_address() or whatever it
        # is called in the compiler does.
        return self.opcode == 0x70 # SFTODO MAGIC 'SB'

    def add_affect(self, affect):
        assert self.is_simple_store() or self.is_simple_load()
        pass

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
        assert isinstance(value, Offset)
        super(LocalLabelInstruction, self).__init__(0xff, [value])

    def dump(self, rld):
        assert isinstance(self.operands[0], Offset) # SFTODO TEMP?
        print("%s" % (self.operands[0]))

    def rename_local_labels(self, alias_dict):
        # rename_local_labels() only affects instructions using a label; we don't rename
        # ourself.
        pass


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
    conditional_branch_pairs = (0x22, 0x24, 0x4c, 0x4e, 0xa0, 0xa2)

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

    def is_conditional_branch(self):
        return self.opcode in self.conditional_branch_pairs

    def invert_condition(self):
        assert self.is_conditional_branch()
        i = self.conditional_branch_pairs.index(self.opcode)
        if i % 2 == 0:
            self._opcode = self.conditional_branch_pairs[i + 1]
        else:
            self._opcode = self.conditional_branch_pairs[i - 1]

    def dump(self, rld):
        # SFTODO: Fold acme_dump_branch() in here? Also used in SelInstruction tho...
        acme_dump_branch(self.opcode, self.operands)

    def rename_local_labels(self, alias_dict):
        self.operands[0] = rename_local_labels(self.operands[0], alias_dict)


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
        self.operands[0].offset = rename_local_labels(self.operands[0].offset, alias_dict)



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

    def add_affect(self, affect):
        super(StackInstruction.self).add_affect(affect)
        assert False


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

    def data_size(self):
        return opdict[self.opcode]['data_size']

    def add_affect(self, affect):
        super(MemoryInstruction,self).add_affect(affect)
        for i in range(0, self.data_size()):
            affect.add(self.operands[0] + i)


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

    def data_size(self):
        return opdict[self.opcode]['data_size']

    def add_affect(self, affect):
        super(FrameInstruction,self).add_affect(affect)
        for i in range(0, self.data_size()):
            affect.add(FrameOffset(self.frame_offset + i))


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
    0x32: {'opcode': 'DROP2', 'dis': StackInstruction.disassemble},
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
    0x60: {'opcode': 'LB', 'is_load': True, 'dis': StackInstruction.disassemble},
    0x62: {'opcode': 'LW', 'is_load': True, 'dis': StackInstruction.disassemble},
    0x64: {'opcode': 'LLB', 'is_load': True, 'data_size': 1, 'dis': FrameInstruction.disassemble},
    0x66: {'opcode': 'LLW', 'is_load': True, 'data_size': 2, 'dis': FrameInstruction.disassemble},
    0x68: {'opcode': 'LAB', 'is_load': True, 'data_size': 1, 'dis': MemoryInstruction.disassemble},
    0x6a: {'opcode': 'LAW', 'is_load': True, 'data_size': 2, 'dis': MemoryInstruction.disassemble},
    0x6c: {'opcode': 'DLB', 'is_load': True, 'is_store': True, 'data_size': 1, 'dis': FrameInstruction.disassemble},
    0x6e: {'opcode': 'DLW', 'is_load': True, 'is_store': True, 'data_size': 2, 'dis': FrameInstruction.disassemble},
    0x70: {'opcode': 'SB', 'is_store': True, 'dis': StackInstruction.disassemble},
    0x72: {'opcode': 'SW', 'is_store': True, 'dis': StackInstruction.disassemble},
    0x74: {'opcode': 'SLB', 'is_store': True, 'data_size': 1, 'dis': FrameInstruction.disassemble},
    0x76: {'opcode': 'SLW', 'is_store': True, 'data_size': 2, 'dis': FrameInstruction.disassemble},
    0x78: {'opcode': 'SAB', 'is_store': True, 'data_size': 1, 'dis': MemoryInstruction.disassemble},
    0x7a: {'opcode': 'SAW', 'is_store': True, 'data_size': 2, 'dis': MemoryInstruction.disassemble},
    0x7c: {'opcode': 'DAB', 'is_load': True, 'is_store': True, 'data_size': 1, 'dis': MemoryInstruction.disassemble},
    0x7e: {'opcode': 'DAW', 'is_load': True, 'is_store': True, 'data_size': 2, 'dis': MemoryInstruction.disassemble},
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
    0xb4: {'opcode': 'ADDAB', 'is_load': True, 'data_size': 1, 'dis': MemoryInstruction.disassemble},
    0xb6: {'opcode': 'ADDAW', 'is_load': True, 'data_size': 2, 'dis': MemoryInstruction.disassemble},
    0xb8: {'opcode': 'IDXLB', 'is_load': True, 'data_size': 1, 'dis': FrameInstruction.disassemble},
    0xba: {'opcode': 'IDXLW', 'is_load': True, 'data_size': 2, 'dis': FrameInstruction.disassemble},
    0xbc: {'opcode': 'IDXAB', 'is_load': True, 'data_size': 1, 'dis': MemoryInstruction.disassemble},
    0xbe: {'opcode': 'IDXAW', 'is_load': True, 'data_size': 2, 'dis': MemoryInstruction.disassemble},
}

class BytecodeFunction(object):
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
                if not isinstance(operand, int): # SFTODO: HACKY
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
        # TODO: I hate the way we need to use .value on lhs and nothing on rhs in next line
        if not (instruction.opcode == 0x50 and next_instruction and next_instruction.is_local_label() and instruction.operands[0] == next_instruction.operands[0]): # SFTODO MAGIC CONST
            new_ops.append(instruction)
        else:
            changed = True
    bytecode_function.ops = new_ops
    return changed


def build_local_label_dictionary(bytecode_function, test):
    result = {}
    for i in range(len(bytecode_function.ops)-1):
        if bytecode_function.ops[i].is_local_label() and test(bytecode_function.ops[i+1]):
            result[bytecode_function.ops[i].operands[0]] = bytecode_function.ops[i+1]
    return result



# This replaces a BRNCH to a LEAVE or RET with the LEAVE or RET itself.
def branch_optimise2(bytecode_function):
    changed = False
    targets = build_local_label_dictionary(bytecode_function, lambda instruction: instruction.opcode in (0x5a, 0x5c)) # SFTODO: MAGIC CONST RET LEAVE
    for i in range(len(bytecode_function.ops)):
        instruction = bytecode_function.ops[i]
        if instruction.opcode == 0x50: # SFTODO MAGIC
            local_label = instruction.operands[0]
            #print('SFTODOQ5', local_label)
            if local_label in targets:
                bytecode_function.ops[i] = targets[local_label]
                changed = True
    return changed

# This replaces the target of a branch (conditional or not) to a BRNCH with the BRNCH's own target.
# TODO: This should also treat CASEBLOCK targets as BRNCH opcodes - which they kind of are. There is at least one case in self-hosted compiled where such a target could be snapped, and it may also then allow the intermediate branch (which follows another unconditional branch) to be removed by the dead code optimisation.
def branch_optimise3(bytecode_function):
    changed = False
    targets = build_local_label_dictionary(bytecode_function, lambda instruction: instruction.opcode == 0x50) # SFTODO MAGIC CONSTANT BRNCH
    alias = {k:v.operands[0] for k, v in targets.items()}
    for i in range(len(bytecode_function.ops)):
        instruction = bytecode_function.ops[i]
        original_operands = copy.deepcopy(instruction.operands) # SFTODO EXPERIMENTAL - THIS IS NOW WORKING, BUT I'D RATHER NOT HAVE TO DO THIS
        #print('SFTODO899 %r' % original_operands)
        instruction.rename_local_labels(alias)
        changed = changed or (original_operands != instruction.operands)
        #print('SFTODO900 %r' % original_operands)
        #print('SFTODO901 %r' % instruction.operands)
    return changed

# Remove local labels which have no instructions referencing them; this can occur as a result
# of other optimisations and is useful in opening up further optimisations.
def remove_orphaned_labels(bytecode_function):
    changed = False
    labels_used = set()
    for instruction in bytecode_function.ops:
        if instruction.operands and not isinstance(instruction.operands[0], int) and not instruction.is_local_label(): # SFTODO HACKY isinstance, as is local label check
            instruction.operands[0].update_local_labels_used(labels_used)
    new_ops = []
    for instruction in bytecode_function.ops:
        if not (instruction.is_local_label() and instruction.operands[0] not in labels_used):
            new_ops.append(instruction)
        else:
            changed = True
    bytecode_function.ops = new_ops
    return changed

# SFTODO: Rename this to is_terminator() and change all comments to use the same terminology
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

# A CASEBLOCK instruction is followed by the 'otherwise' instructions. If those instructions
# are a logically isolated block, the CASEBLOCK+otherwise instructions can be moved to the end
# of the function. This may allow a BRNCH instruction which is there just to skip over the
# CASEBLOCK to be optimised away.
def move_caseblocks(bytecode_function):
    tail = []
    i = 0
    while i < len(bytecode_function.ops):
        if bytecode_function.ops[i].opcode == 0xfb and bytecode_function.ops[i-2].opcode == 0x50: # SFTODO MAGIC CONST CASEBLOCK, BRNCH
            assert bytecode_function.ops[i-1].is_local_label()
            j = i
            while j < len(bytecode_function.ops)-1:
                j += 1
                instruction2 = bytecode_function.ops[j]
                if instruction2.is_local_label():
                    i = j
                    break
                if never_immediate_successor(instruction2.opcode):
                    for k in range(i-1, j+1):
                        tail.append(bytecode_function.ops[k])
                        bytecode_function.ops[k] = NopInstruction()
                    i = j
                    break
        i += 1
    original_ops = bytecode_function.ops
    bytecode_function.ops = [op for op in bytecode_function.ops if op.opcode != 0xf1] # SFTODO MAGIC CONSTANT NOP
    for i in range(len(bytecode_function.ops)-1):
        if bytecode_function.ops[i].opcode == 0xf1 and bytecode_function.ops[i+1].opcode != 0xf1:
            break
    bytecode_function.ops += tail
    changed = bytecode_function.ops != original_ops 
    return changed

# SFTODO: EXPERIMENTAL
class Foo(object):
    def __init__(self, bytecode_function):
        self.ops = bytecode_function.ops
        self.blocks_metadata = [None]
        self.block_starts = [0]
        self.start = 0

    def start_before(self, i, metadata):
        start = self.block_starts[-1]
        assert start <= i
        assert i <= len(self.ops)
        if start == i:
            assert self.blocks_metadata[-1] is None
            self.blocks_metadata[-1] = metadata
        else:
            self.block_starts.append(i)
            self.blocks_metadata.append(metadata)

    def start_after(self, i, metadata):
        self.start_before(i + 1, metadata)

    def get_blocks_and_metadata(self):
        if self.block_starts[-1] < len(self.ops):
            self.start_before(len(self.ops), None)
        blocks = []
        for start, end in zip(self.block_starts, self.block_starts[1:]):
            blocks.append(self.ops[start:end])
        assert len(blocks) == len(self.blocks_metadata)-1
        assert sum(len(block) for block in blocks) == len(self.ops)
        return blocks, self.blocks_metadata[:-1]



# SFTODO: In following fns and their callers, should I stop saying 'metadata' and say
# 'label', because that's what it is in these cases? It may turn out that Foo() is used
# in cases where the metadata is something else, so that's fine, but the below do
# specifically use labels.


# SFTODO: EXPERIMENTAL - SEEMS QUITE PROMISING, TRY USING THIS IN block_move() AND THEN OTHERS
def get_blocks(bytecode_function):
    foo = Foo(bytecode_function)
    for i, instruction in enumerate(bytecode_function.ops):
        if instruction.is_local_label():
            foo.start_before(i, instruction.operands[0])
        elif never_immediate_successor(instruction.opcode):
            foo.start_after(i, None)
    return foo.get_blocks_and_metadata()

# Split a function up into blocks:
# - blocks which start with a local label, contain a series of non-label
#   instructions and end with an instruction transferring control elsewhere.
# - anonymous blocks which don't satisfy that condition
# We also classify named blocks such that block_label_only[i] is True iff
# control only reaches that block via its label (not by falling off the end
# of the previous block); such blocks can be freely moved around.
def get_blocks2(bytecode_function): # SFTODO POOR NAME
    blocks, blocks_metadata = get_blocks(bytecode_function)
    block_label_only = [False] * len(blocks)
    for i, block in enumerate(blocks):
        assert block # SFTODO: I think the split code can never generate an empty block - if so we can remove the following if...
        if block:
            if not never_immediate_successor(block[-1].opcode):
                blocks_metadata[i] = None
            else:
                block_label_only[i] = i > 0 and blocks[i-1] and never_immediate_successor(blocks[i-1][-1].opcode)
    return blocks, blocks_metadata, block_label_only

def block_deduplicate(bytecode_function):
    blocks, blocks_metadata, block_label_only = get_blocks2(bytecode_function)

    # Compare each pair of non-anonymous blocks (ignoring the initial local
    # label); if two are identical and one of them is never entered by falling
    # through from the previous block, we can delete that one and replace all
    # references to its label with the label of the other block.
    alias = {}
    unwanted = set()
    for i in range(len(blocks)):
        for j in range(i+1, len(blocks)):
            if blocks_metadata[i] and blocks_metadata[j] and blocks[i][1:] == blocks[j][1:]:
                assert blocks[i][0].is_local_label()
                assert blocks[j][0].is_local_label()
                replace = None
                # SFTODO: Isn't this code subtly wrong? In the 'if' case, for example,
                # what if block[j] is in unwanted? We'd generate calls to its label
                # even though it's being removed.
                if blocks_metadata[i] not in unwanted and block_label_only[i]:
                    replace = (blocks_metadata[i], blocks_metadata[j])
                elif blocks_metadata[j] not in unwanted and block_label_only[j]:
                    replace = (blocks_metadata[j], blocks_metadata[i])
                if replace:
                    alias[replace[0]] = replace[1]
                    unwanted.add(replace[0])

    # Now rebuild the function from the blocks.
    new_ops = []
    changed = False
    assert None not in unwanted
    for i, block in enumerate(blocks):
        if blocks_metadata[i] not in unwanted:
            for instruction in block:
                instruction.rename_local_labels(alias)
                new_ops.append(instruction)
        else:
            changed = True
    bytecode_function.ops = new_ops

    return changed


# Look for blocks of code within a function which cannot be entered except via their
# label and see if we can move those blocks to avoid the need to BRNCH to them.
def block_move(bytecode_function):
    # In order to avoid gratuitously moving chunks of code around (which makes it
    # harder to verify the transformations performed by this valid), we remove any
    # redundant branches to the immediately following instruction first.
    branch_optimise(bytecode_function)

    blocks, blocks_metadata, block_label_only = get_blocks2(bytecode_function)

    # Merge blocks where possible.
    changed = False
    for i, block in enumerate(blocks):
        if block and block[-1].opcode == 0x50: # SFTODO MAGIC BRNCH
            target_label = block[-1].operands[0]
            if target_label in blocks_metadata:
                target_block_index = blocks_metadata.index(target_label)
                if target_block_index != i and block_label_only[target_block_index]:
                    blocks[i] = blocks[i][:-1] + blocks[target_block_index]
                    blocks[target_block_index] = []
                    blocks_metadata[target_block_index] = None
                    changed = True

    # Regenerate the function from the modified blocks.
    new_ops = []
    for block in blocks:
        new_ops.extend(block)
    bytecode_function.ops = new_ops

    return changed



# If the same instruction occurs before all unconditional branches to a label, and there are
# no conditional branches to the label, the instruction can be moved immediately after the
# label.
def tail_move(bytecode_function):
    # For every local label, set candidates[label] to:
    # - the unique preceding instruction for all unconditional branches to it, provided it has
    #   no conditional branches to it, or
    # - None otherwise.
    candidates = {}
    for i in range(len(bytecode_function.ops)):
        instruction = bytecode_function.ops[i]
        if i > 0 and instruction.opcode == 0x50: # SFTODO MAGIC BRNCH
            previous_instruction = bytecode_function.ops[i-1]
            if never_immediate_successor(previous_instruction.opcode):
                # This branch can never actually be reached; it will be optimised away
                # eventually (it probably already has and this case won't occur) but
                # it's not correct to move the preceding instruction on the assumption
                # this branch will be unconditionally taken.
                continue
            label = instruction.operands[0]
            if candidates.setdefault(label, previous_instruction) != previous_instruction:
                candidates[label] = None
        else:
            if instruction.operands and not isinstance(instruction.operands[0], int) and not instruction.is_local_label(): # SFTODO HACKY isinstance, not local label is also hacky
                labels_used = set()
                instruction.operands[0].update_local_labels_used(labels_used)
                for label in labels_used:
                    candidates[label] = None

    # Now check the immediately preceding instruction before every local label with a
    # candidate. If it's not a terminator and it doesn't match the candidate, the
    # candidate must be discarded. Otherwise we insert the candidate after the label
    # and remove any copy of the candidate immediately preceding the label. (We don't
    # remove instances of the candidate before unconditional branches here, because
    # until we've finished this loop we can't be sure a candidate won't be discarded.)
    new_ops = []
    changed = False
    for instruction in bytecode_function.ops:
        new_ops.append(instruction)
        if len(new_ops) >= 2 and instruction.is_local_label():
            candidate = candidates.get(instruction.operands[0], None)
            if candidate:
                previous_instruction = new_ops[-2]
                assert not previous_instruction.is_local_label()
                if not never_immediate_successor(previous_instruction.opcode):
                    if previous_instruction != candidate:
                        candidates[instruction.operands[0]] = None
                        continue
                    new_ops.pop(-2) # remove previous_instruction
                new_ops.append(candidate)
                changed = True

    # We can now go ahead and remove all instances of candidates before unconditional
    # branches.
    if changed:
        i = 0
        while i < len(new_ops):
            instruction = new_ops[i]
            if i > 0 and instruction.opcode == 0x50: # SFTODO MAGIC BRNCH
                label = instruction.operands[0]
                if label in candidates:
                    candidate = candidates[label]
                    if candidate:
                        new_ops[i-1] = NopInstruction()
            i += 1
        bytecode_function.ops = [op for op in new_ops if op.opcode != 0xf1]

    return changed



def peephole_optimise(bytecode_function):
    changed = False
    i = 0
    bytecode_function.ops += [NopInstruction(), NopInstruction()] # add dummy NOPs so we can use ops[i+2] freely
    while i < len(bytecode_function.ops)-2:
        instruction = bytecode_function.ops[i]
        next_instruction = bytecode_function.ops[i+1]
        next_next_instruction = bytecode_function.ops[i+2]
        # DROP:DROP -> DROP
        if instruction.opcode == 0x30 and next_instruction.opcode == 0x30: # SFTODO MAGIC 'DROP'
            bytecode_function.ops[i] = StackInstruction(0x32) # SFTODO MAGIC DROP2
            bytecode_function.ops[i+1] = NopInstruction()
            changed = True
        # BRTRU x:BRNCH y:x -> BRFLS y:x (and similar)
        elif instruction.is_conditional_branch() and next_instruction.opcode == 0x50 and next_next_instruction.is_local_label() and instruction.operands[0] == next_next_instruction.operands[0]: # SFTODO MAGIC BRNCH
            bytecode_function.ops[i].invert_condition()
            bytecode_function.ops[i].operands = next_instruction.operands
            bytecode_function.ops[i+1] = NopInstruction()
            changed = True
        # TODO: Delete the following - it doesn't actually occur, because there's always an 
        # intervening label which stops this optimisation.
        #elif instruction.opcode in (0x40, 0x42) and next_instruction.opcode in (0x4c, 0x4e): # SFTODO MAGIC - ISEQ/ISNE, BRFLS/BRTRU
        #    new_opcode = {(0x40, 0x4c): 0x24, # SFTODO MAGIC BRNE
        #                  (0x40, 0x4e): 0x22, # SFTODO MAGIC BREQ
        #                  (0x42, 0x4c): 0x22,
        #                  (0x42, 0x4e): 0x24}[(instruction.opcode, next_instruction.opcode)]
        #    bytecode_function.ops[i] = NopInstruction()
        #    bytecode_function.ops[i+1] = BranchInstruction(new_opcode, bytecode_function.ops[i+1].operands[0].value)
        #    changed = True
        # TODO: This optimisation is temporarily disabled as it is a very hacky implementation. I think it may be worth writing a more general version, if nothing else it would likely cause me to think up some useful general predicates ('get affected addresses', perhaps returning a generic list which can handle all kinds of load/store addresses) on the instruction classes. Note that this optimisation will increase use of the expression stack by one, so it should be separately controllable as it just may break code which is pushing the expression stack size.
        elif False and instruction.opcode == 0x66 and next_instruction.is_store() and instruction == next_next_instruction: # SFTODO: MAGIC CONST LLW - ALSO THIS OPTIMISATION COULD IN PRINCIPLE BE DONE IN A MUCH MORE GENERAL WAY ALLOWING FOR LONGER SERIES OF INTERVENING INSTRUCTIONS ETC, BUT THIS IS A FIRST CUT
            frame_offset = instruction.frame_offset
            if not (isinstance(next_instruction, FrameOffset) and abs(frame_offset - next_instruction.frame_offset) < 2): # SFTODO: RIDICULOUSLY OVER-CONSERVATIVE WAY TO CHECK THIS, JUST FOR EXPEDIENCY
                bytecode_function.ops[i+2] = bytecode_function.ops[i+1]
                bytecode_function.ops[i+1] = StackInstruction(0x34) # SFTODO MAGIC DUP
                changed = True
        elif instruction.is_simple_store() and not instruction.is_load() and not instruction.has_side_effects() and next_instruction.is_simple_load() and not next_instruction.is_store() and not next_instruction.has_side_effects() and instruction.operands[0] == next_instruction.operands[0] and instruction.data_size() == next_instruction.data_size():
            dup_for_store = {0x7a: 0x7e, # SFTODO MAGIC CONSTANTS
                             0x78: 0x7c,
                             0x74: 0x6c,
                             0x76: 0x6e}
            bytecode_function.ops[i] = instruction.__class__(dup_for_store[instruction.opcode], instruction.operands[0])
            bytecode_function.ops[i+1] = NopInstruction()
            changed = True
        i += 1
    bytecode_function.ops = bytecode_function.ops[:-2] # remove dummy NOP
    changed = changed or any(op.opcode == 0xf1 for op in bytecode_function.ops) # SFTODO MAGIC
    bytecode_function.ops = [op for op in bytecode_function.ops if op.opcode != 0xf1]
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

def calculate_lla_threshold(bytecode_function):
    lla_threshold = 256
    for instruction in bytecode_function.ops:
        if instruction.opcode == 0x28: # SFTODO MAGIC CONSTANT 'LLA'
            lla_threshold = min(instruction.operands[0].value, lla_threshold)
    return lla_threshold

def disjoint_affect(lhs, rhs):
    #print("SFTODOX1 %r", lhs)
    #print("SFTODOX2 %r", rhs)
    return len(lhs.intersection(rhs)) == 0

# TODO: This optimisation will increase expression stack usage, which might break some
# programs - it should probably be controlled separately (e.g. -O3 only, and/or a
# --risky-optimisations switch)
def load_to_dup(bytecode_function, straightline_ops):
    lla_threshold = calculate_lla_threshold(bytecode_function)

    changed = False
    for i in range(len(straightline_ops)):
        instruction = straightline_ops[i]
        if instruction.is_simple_load() and not instruction.is_store() and not instruction.has_side_effects():
            stores_affect = set()
            j = i + 1
            while j < len(straightline_ops):
                if straightline_ops[j].is_simple_store():
                    straightline_ops[j].add_affect(stores_affect)
                    if not straightline_ops[j].is_load():
                        j += 1
                        break
                else:
                    break
                j += 1
            if j < len(straightline_ops) and instruction == straightline_ops[j]:
                # We have a load, zero or more "dup stores", a store and an identical load.
                # Provided none of the intervening stores modify the data loaded and the
                # load has no side effects, we can replace the initial load with a load:DUP
                # and remove the final load. 
                loads_affect = set()
                instruction.add_affect(loads_affect)
                if disjoint_affect(loads_affect, stores_affect):
                    for k in range(j, i+1, -1):
                        straightline_ops[k] = straightline_ops[k-1]
                    straightline_ops[i+1] = StackInstruction(0x34) # SFTODO MAGIC DUP
                    changed = True

    return straightline_ops, changed

def optimise_load_store(bytecode_function, straightline_ops):
    lla_threshold = calculate_lla_threshold(bytecode_function)

    store_index_visibly_affected_bytes = [None] * 256
    last_store_index_for_offset = [None] * 256

    def record_store(this_store_index, frame_offsets):
        changed = False
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
        return changed

    def record_load(frame_offsets):
        for frame_offset in frame_offsets:
            last_store_index = last_store_index_for_offset[frame_offset]
            if last_store_index:
                store_index_visibly_affected_bytes[last_store_index] = None

    changed = False
    for i in range(len(straightline_ops)):
        instruction = straightline_ops[i]
        opcode, operands = instruction.opcode, instruction.operands
        opdef = opdict.get(opcode, None)
        if opdef:
            is_store = isinstance(instruction, FrameInstruction) and opdef.get('is_store', False)
            is_load = isinstance(instruction, FrameInstruction) and opdef.get('is_load', False)
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
                changed = record_store(i, frame_offsets) or changed
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
                changed = record_store(i, range(0, 256)) or changed

    return [op for op in straightline_ops if op.opcode != 0xf1], changed


class Module(object):
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

SFTODOFLAG = True
def SFTODO(ops):
    return True# SFTODO!?
    global SFTODOFLAG
    if len(ops) < 4:
        return True
    i = 0
    while i < len(ops) - 3:
        if isinstance(ops[i], LocalLabelInstruction) and ops[i].operands[0] == Offset('_L0426'):
            pass #print('SFTODOqqq')
        if isinstance(ops[i], ConstantInstruction) and ops[i].operands[0] == -1 and ops[i+1].opcode == 0x5c and isinstance(ops[i+2], ConstantInstruction) and ops[i+2].operands[0] == -1 and ops[i+3].opcode == 0x5c:
            return False 
        i += 1
    SFTODOFLAG = False 
    return True

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
    SFTODOFLAG = True
    assert SFTODO(bytecode_function.ops)
    while changed:
        changed1 = True
        while changed1:
            # TODO: This seems a clunky way to handle 'changed' but I don't want
            # short-circuit evaluation. I think we can do 'changed = function() or changed', if
            # we want...
            result = []
            if True: # SFTODO TEMP
                #SFTODO = copy.deepcopy(bytecode_function.ops)
                result.append(local_label_deduplicate(bytecode_function))
                assert SFTODO(bytecode_function.ops)
                #assert result[-1] or (SFTODO == bytecode_function.ops)
                result.append(branch_optimise(bytecode_function))
                assert SFTODO(bytecode_function.ops)
                result.append(branch_optimise2(bytecode_function))
                assert SFTODO(bytecode_function.ops)
                result.append(branch_optimise3(bytecode_function))
                assert SFTODO(bytecode_function.ops)
                result.append(remove_orphaned_labels(bytecode_function))
                assert SFTODO(bytecode_function.ops)
                result.append(remove_dead_code(bytecode_function))
                assert SFTODO(bytecode_function.ops)
                result.append(straightline_optimise(bytecode_function, [optimise_load_store, load_to_dup]))
                assert SFTODO(bytecode_function.ops)
                result.append(move_caseblocks(bytecode_function))
                assert SFTODO(bytecode_function.ops)
                result.append(peephole_optimise(bytecode_function))
                assert SFTODO(bytecode_function.ops)
                #if SFTODOFOO:
                #    break
            changed1 = any(result)
        #remove_dead_code(bytecode_function) # SFTODO
        changed2 = True
        # We do these following optimisations only when the ones above fail to produce any
        # effect. These can reorder code but this can give (slightly) unhelpful/confusing
        # re-orderings, so we let the more localised optimisations above have first go.
        # TODO: It may be worth putting all this back into a single loop later on to see if
        # this is actually still true.
        while changed2:
            result = []
            assert SFTODO(bytecode_function.ops)
            result.append(block_deduplicate(bytecode_function))
            assert SFTODO(bytecode_function.ops)
            result.append(block_move(bytecode_function))
            assert SFTODO(bytecode_function.ops)
            result.append(tail_move(bytecode_function))
            assert SFTODO(bytecode_function.ops)
            changed2 = any(result)
        changed = changed1 or changed2
    bytecode_function.dump(new_rld, new_esd)
used_things_ordered[-1].dump(new_rld, new_esd)
defcnt = len(used_things_ordered)

print("_DEFCNT = %d" % (defcnt,))
print("_SEGEND")
print(";\n; RE-LOCATEABLE DICTIONARY\n;")

new_rld.dump()

new_esd.dump()

# TODO: Would it be worth replacing "CN 1:SHL" with "DUP:ADD"? This occurs in the self-hosted compiler at least once. It's the same length, so would need to cycle count to see if it's faster.

# TODO: "LLW [n]:SAW x:LLW [n]" -> "LLW [n]:DAW x"? Occurs at least once in self-hosted compiler. I think this is better (where possible) than the expression-stack-use-increasing optimisation I have using DUP. This pattern of observation (provided the loads have no side effects; we aren't optimising away the store so it's fine if it does) applies generally; LOAD foo:STORE bar:LOAD foo can be optimised to LOAD foo:DUPSTORE bar. There's a corner case where foo and bar partially overlap (if they fully overlap it's fine), so we shouldn't optimise if that's the case.

# TODO: Perhaps not worth it, and this is a space-not-speed optimisation, but if it's common to CALL a function FOO and then immediately do a DROP afterwards (across all code in the module, not just one function), it may be a space-saving win to generate a function FOO-PRIME which does "(no ENTER):CALL FOO:DROP:RET" and replace CALL FOO:DROP with CALL FOO-PRIME. We could potentially generalise this (we couldn't do it over multiple passes) to recognising the longest common sequence of operations occurring after all CALLs to FOO and factoring them all into FOO-PRIME.
