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

# SFTODO: Experimental
class ComparisonMixin(object):
    def __hash__(self):
        return hash(self.keys())

    def __eq__(self, other):
        if type(self) == type(other):
            return self.keys() == other.keys()
        return False

    def __ne__(self, other):
        return not self == other



# TODO: Not sure about this base class, it's just here to allow assertions on type of operands at the moment!
class AbsoluteAddress(object):
    """Base class for operands which represent an absolute memory address"""

    @classmethod
    def disassemble(cls, di, i):
        address = di.labelled_blob.references[i]
        if address:
            assert isinstance(address, Label) or isinstance(address, ExternalReference)
            return address, i+2
        else:
            return FixedAddress.disassemble(di, i)


class Label(AbsoluteAddress, ComparisonMixin):
    __next = collections.defaultdict(int)

    def __init__(self, prefix, add_suffix = True):
        # We don't need to populate self.owner here; we are either creating a Label object
        # to be initially associated with the single LabelledBlob corresponding to the whole
        # input module, which will be sliced up later on, or we are creating Label objects
        # only as part of dump() in which case no one cares about ownership.
        self.owner = None

        if add_suffix:
            i = Label.__next[prefix]
            self.name = '%s%04d' % (prefix, i)
            Label.__next[prefix] += 1
        else:
            self.name = prefix

    def set_owner(self, owner):
        self.owner = owner

    def keys(self):
        return (self.name,)

    def __add__(self, rhs):
        # SFTODO: This is a bit odd. We need this for memory(). However, I *think* that
        # since we evidently have no need to support the concept of "label+n" anywhere,
        # we can get away with just returning self here - because if it's impossible to
        # represent the concept of "label+1", there is no scope for one bit of code to e.g.
        # LAW label and another bit of code to SAB label+1 and the two to "clash".
        # SFTODO: I think that is true, *but* it suggests that we may be able to optimise
        # things (presumably code which wants to access offset from a label may have to do
        # LA LABEL:ADDI 3:LB and we might be able to turn that into LA LABEL+3 - this is
        # complete speculation right now, I haven't checked any real code) by allowing the
        # concept of label+n in this code.
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

    # TODO: This function should probably be renamed (everywhere, not just here)
    def update_used_things(self, used_things):
        self.owner.update_used_things(used_things)

class ExternalReference(AbsoluteAddress, ComparisonMixin):
    def __init__(self, external_name, offset):
        self.external_name = external_name
        self.offset = offset

    def keys(self):
        return (self.external_name, self.offset)

    def __add__(self, rhs):
        assert isinstance(rhs, int)
        return ExternalReference(self.external_name, self.offset + rhs)
        
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
        # a huge load time difference, but it's probably a good idea - especially as output from
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
        assert isinstance(reference, Label)
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
        for label_list in b.labels:
            for label in label_list:
                label.set_owner(b)
        b.references = self.references[start:end]
        return b

    def label(self, key, lbl):
        self.labels[key].append(lbl)

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

    def update_used_things(self, used_things):
        if self in used_things:
            return
        used_things.add(self)
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


class Byte(ComparisonMixin):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return "%d" % (self.value,)

    def __repr__(self):
        return "Byte(%d)" % (self.value,)

    def keys(self):
        return (self.value,)

    def acme(self):
        return "$%02X" % (self.value,)

    # TODO: Why does Byte need a disassemble method but FrameOffset doesn't?
    @classmethod
    def disassemble(cls, di, i):
        byte = cls(di.labelled_blob[i])
        return byte, i+1


class FrameOffset(Byte):
    def __add__(self, rhs):
        assert isinstance(rhs, int)
        return FrameOffset(self.value + rhs)



class FixedAddress(AbsoluteAddress, ComparisonMixin):
    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return "FixedAddress($%04X)" % (self.value,)

    def __keys__(self):
        return (self.value,)

    def __add__(self, rhs):
        assert isinstance(rhs, int)
        return FixedAddress(self.value + rhs)

    def update_used_things(self, used_things):
        pass

    # SFTODO: Shouldn't we "need" an acme() method on this?

    @classmethod
    def disassemble(cls, di, i):
        return FixedAddress(di.labelled_blob.read_u16(i)), i+2


# https://stackoverflow.com/questions/32030412/twos-complement-sign-extension-python
def sign_extend(value, bits=16):
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
    assert isinstance(alias, dict)
    assert all(isinstance(k, Offset) and isinstance(v, Offset) for k,v in alias.items())
    return Offset(alias.get(offset, offset)._value)


# SFTODO: I think I want to rename this LocalLabel, but let's not worry about that just yet.
# SFTODO: May be worth jumping through some Python hoops (I think essentially involving
# deriving from namedtuple and setting slots to empty) to make this truly immutable, to avoid
# the risk of confusing myself (given that the same Offset object may be shared by multiple
# instructions and changes are likely to have the wrong effect).
class Offset(ComparisonMixin):
    def __init__(self, value):
        assert isinstance(value, str)
        self._value = value

    def __str__(self):
        return self._value

    def __repr__(self):
        return "Offset(%s)" % (self._value,)

    def keys(self):
        return (self._value,)

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
        value = sign_extend(value)
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
                    di.bytecode_function.ops.insert(j, Instruction(LOCAL_LABEL_OPCODE, [local_label]))
                    j = 99999 # SFTODO ULTRA FOUL
                j += 1
            assert j >= 99999
        return local_label, i+2




class CaseBlock(ComparisonMixin):
    def __init__(self, table):
        self.table = table

    def __repr__(self):
        return "CaseBlock(%d)" % (len(self.table),)

    def keys(self):
        return (self.table,)

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


class String(ComparisonMixin):
    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return "String(%r)" % (self.value,)

    def keys(self):
        return (self.value,)

    @classmethod
    def disassemble(cls, di, i):
        length = di.labelled_blob[i]
        s = ''
        for j in range(length):
            s += chr(di.labelled_blob[i + j + 1])
        return String(s), i + length + 1


# TODO: Seems wrong to have these random free functions

def acme_dump_branch(opcode, operands):
    print("\t!BYTE\t$%02X\t\t\t; %s\t%s" % (opcode, opdict[opcode]['opcode'], operands[0]))
    print("\t!WORD\t%s-*" % (operands[0],))

def acme_dump_label(opcode, operands, rld):
    if isinstance(operands[0], FixedAddress): # SFTODO: Bit crap - shouldn't this be a polymorphic thing?
        print("\t!BYTE\t$%02X,$%02X,$%02X\t\t; %s\t$%04X" % (opcode, operands[0].value & 0xff, (operands[0].value & 0xff00) >> 8, opdict[opcode]['opcode'], operands[0].value))
    else:
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

def acme_dump_case_block(opcode, operands):
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
        self.local_target = [[] for _ in range(len(labelled_blob))] # SFTODO VERY EXPERIMENTAL
        self.special = [None] * len(labelled_blob) # SFTODO: COULD USE FALSE? OR JUST HAVE A DICT?
        self.op_offset = []


# TODO: At least temporarily while Instruction objects can be constructed directly during transition, I am not doing things like overriding is_local_label() in the relevant derived class, because it breaks when an actual base-class Instruction object is constructed
class Instruction(ComparisonMixin):
    conditional_branch_pairs = (0x22, 0x24, 0x4c, 0x4e, 0xa0, 0xa2)

    def __init__(self, opcode, operands = None):
        self.set(opcode, operands)

    def set(self, opcode2, operands = None): # SFTODO OPCODE2 - CRAP NAME TO AVOID CLASH
        if isinstance(opcode2, Instruction):
            assert not operands
            self._opcode = opcode2._opcode
            self.operands = opcode2.operands
        else:
            assert operands is None or isinstance(operands, list)
            if isinstance(opcode2, str):
                opcode2 = opcode[opcode2]
            else:
                assert isinstance(opcode2, int)
            self._opcode = opcode2
            self.operands = operands if operands else []
        ic = instruction_class_fns[self.instruction_class]
        # SFTODO: Might be nice if (perhaps via a property or something) we performed the
        # following validation after any direct update to the operands as well - code just
        # updates self.operands directly at the moment without this class's code getting
        # involved.
        assert len(self.operands) == ic['operands']
        assert all(isinstance(operand, ic['operand_type']) for operand in self.operands)

    def keys(self):
        return (self._opcode, self.operands)

    # It may or may not be Pythonic but we use a property here to prevent code accidentally
    # changing the opcode. Doing so would lead to subtle problems because the type of the
    # object wouldn't change. SFTODO: Quite possibly will leave this as it is, but now we
    # don't have derived classes the type changing issue doesn't arise.
    @property
    def opcode(self):
        return self._opcode

    def is_a(self, *mnemonics): # SFTODO: Use this everywhere appropriate - I don't like the name so can maybe think of a better one, but want something short as 'is' alone is a reserved word
        return any(self._opcode == opcode[mnemonic] for mnemonic in mnemonics)

    def is_local_label(self):
        return self.opcode == LOCAL_LABEL_OPCODE

    def is_branch(self):
        # SFTODO: TRANSITION
        if self.instruction_class in (InstructionClass.BRANCH, InstructionClass.SEL):
            return True
        return False

    # SFTODO: Somewhat confusing name - while what we do is correct, INCBRLE for example is *not*
    # a conditional branch according to this.
    def is_conditional_branch(self):
        # SFTODO: TRANSITION
        if self.instruction_class == InstructionClass.BRANCH:
            return self.opcode in self.conditional_branch_pairs
        return False

    def invert_condition(self):
        assert self.is_conditional_branch()
        i = self.conditional_branch_pairs.index(self.opcode)
        self._opcode = self.conditional_branch_pairs[i ^ 1]

    def is_store(self):
        return opdict[self.opcode].get('is_store', False)

    def is_simple_store(self):
        # TODO: This is a bit of a hack but let's see how it goes
        return self.is_store() and not self.is_a('SB', 'SW')

    def is_dup_store(self):
        return opdict[self.opcode].get('is_dup_store', False)

    def is_load(self):
        return opdict[self.opcode].get('is_load', False)

    def is_simple_load(self):
        # TODO: This is a bit of a hack but let's see how it goes
        return self.is_load() and self.opcode not in (0x60, 0x62, 0xb0, 0xb2, 0xb4, 0xb6, 0xb8, 0xba, 0xbc, 0xbe)

    def is_simple_stack_push(self):
        # TODO: I am using has_side_effects() as a proxy for "doesn't access memory mapped I/O" here
        # TODO: I am probably missing some possible instructions here, but for now let's keep it simple
        return (self.is_simple_load() and not self.has_side_effects()) or self.instruction_class == InstructionClass.CONSTANT


    def has_side_effects(self):
        # SFTODO: Once I actually start supporting loads/stores to absolute addresses,
        # this needs to return True for those just as is_hardware_address() or whatever it
        # is called in the compiler does.
        # SFTODO: So while I want to review where it's called etc, this should probably be using the new is_hardware_address() function added to this file
        return self.opcode == 0x70 # SFTODO MAGIC 'SB' - THIS IS PROBABLY CRAP *ANYWAY*, BUT WE SHOULD ALMOST CERTAINLY TREAT 'SW' THE SAME, AND WE DON'T - CHECK BEFORE REMOVING THIS, BUT I BELIEVE ALL CALLERS OF THIS HAVE ALREADY EXCLUDED 'SB' (AND 'SW' AND 'LB' AND 'LW') BY CHECKING FOR 'SIMPLE' LOAD/STORE, SO I REALLY THINK THIS JUST MEANS ACCESSES (OR MAY ACCESS; WE COULD JUST ASSERT OPCODE IS NOT SB/SW/LB/LW HERE, BUT WE COULD RETURN TRUE FOR THOSE OPCODES ANYWAY - ACTUALLY I GUESS THAT IS WHY WE SPECIAL CASED 'SB' TO START WITH) *HARDWARE ADDRESS* AND NOTHING ELSE

    @property
    def instruction_class(self):
        return opdict[self.opcode]['class']

    def update_used_things(self, used_things):
        # SFTODO TEMP HACK FOR TRANSITION
        if self.instruction_class in (InstructionClass.CONSTANT, InstructionClass.LOCAL_LABEL, InstructionClass.BRANCH, InstructionClass.STACK, InstructionClass.IMMEDIATE1, InstructionClass.IMMEDIATE2, InstructionClass.FRAME, InstructionClass.STRING, InstructionClass.SEL, InstructionClass.CASE_BLOCK):
            pass
        elif self.instruction_class == InstructionClass.ABSOLUTE:
            self.operands[0].update_used_things(used_things)
        else:
            assert False # SFTODO SHOULD BE HANDLED BY DERIVED CLASS
            
    def rename_local_labels(self, alias_dict):
        # SFTODO TEMP HACK FOR TRANSITION
        if self.instruction_class in (InstructionClass.CONSTANT, InstructionClass.LOCAL_LABEL, InstructionClass.STACK, InstructionClass.IMMEDIATE1, InstructionClass.IMMEDIATE2, InstructionClass.ABSOLUTE, InstructionClass.FRAME, InstructionClass.STRING):
            pass
        elif self.instruction_class == InstructionClass.BRANCH:
            self.operands[0] = rename_local_labels(self.operands[0], alias_dict)
        elif self.instruction_class == InstructionClass.SEL:
            self.operands[0] = rename_local_labels(self.operands[0], alias_dict)
        elif self.instruction_class == InstructionClass.CASE_BLOCK:
            self.operands[0].rename_local_labels(alias_dict)
        else:
            assert False # SFTODO SHOULD BE HANDLED BY DERIVED CLASS

    def update_local_labels_used(self, labels_used):
        # SFTODO TEMP HACK FOR TRANSITION
        if self.instruction_class in (InstructionClass.CONSTANT, InstructionClass.LOCAL_LABEL, InstructionClass.STACK, InstructionClass.IMMEDIATE1, InstructionClass.IMMEDIATE2, InstructionClass.ABSOLUTE, InstructionClass.FRAME, InstructionClass.STRING):
            pass
        elif self.instruction_class in (InstructionClass.BRANCH, InstructionClass.SEL, InstructionClass.CASE_BLOCK):
            self.operands[0].update_local_labels_used(labels_used)
        else:
            assert False # SFTODO SHOULD BE HANDLED BY DERIVED CLASS

    def memory(self):
        assert self.instruction_class in (InstructionClass.ABSOLUTE, InstructionClass.FRAME)
        result = set()
        for i in range(0, self.data_size()):
            result.add(self.operands[0] + i)
        return result

    def data_size(self):
        assert self.instruction_class in (InstructionClass.ABSOLUTE, InstructionClass.FRAME)
        return opdict[self.opcode]['data_size']

    def dump(self, rld): # SFTODO: RENAME SELF
        instruction_class_fns[self.instruction_class]['dump'](self, rld)





# TODO: Probably rename Instruction to Op and make corresponding changes in all other class and
# variable names; 'Instruction' is fine in itself, but it's super verbose and it appears one way
# or another all over the code.


# TODO: Crappy way to define this pseudo-opcode
CONSTANT_OPCODE = 0xe1 # SFTODO USE A CONTIGUOUS RANGE FOR ALL PSEUDO-OPCODES
LOCAL_LABEL_OPCODE = 0xff
NOP_OPCODE = 0xf1
CASE_BLOCK_OPCODE = 0xfb

# TODO: More probably unsatisfactory free functions

def disassemble_constant(disassembly_info, i):
    opcode = disassembly_info.labelled_blob[i]
    if opcode <= 0x1e: # CN opcode
        return Instruction(CONSTANT_OPCODE, [opcode/2]), i+1
    elif opcode == 0x20: # MINUS ONE opcode
        return Instruction(CONSTANT_OPCODE, [-1]), i+1
    elif opcode == 0x2a: # CB opcode
        return Instruction(CONSTANT_OPCODE, [disassembly_info.labelled_blob[i+1]]), i+2
    elif opcode == 0x2c: # CW opcode
        return Instruction(CONSTANT_OPCODE, [sign_extend(disassembly_info.labelled_blob.read_u16(i+1))]), i+3
    elif opcode == 0x5e: # CFFB opcode
        return Instruction(CONSTANT_OPCODE, [0xff00 | disassembly_info.labelled_blob[i+1]]), i+2
    else:
        print('SFTODO %02x' % opcode)
        assert False

def dump_constant(self, rld): # SFTODO: SHOULD RENAME FIRST ARG
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


class InstructionClass:
    CONSTANT = 0
    LOCAL_LABEL = 1
    NOP = 2
    BRANCH = 3
    STACK = 4 # SFTODO: RENAME IMPLIED?
    IMMEDIATE1 = 5
    IMMEDIATE2 = 6
    ABSOLUTE = 7
    FRAME = 8
    STRING = 9
    SEL = 10
    CASE_BLOCK = 11


# SFTODO: Should I rename LocalLabel (and variants) to BranchTarget? I like the term local label in itself, but it maybe invites confusion with Label (which is a whole-module concept, not a function-level concept)

# TODO: More random free functions

def dump_local_label(self, rld): # SFTODO: RENAME FIRST ARG
    assert isinstance(self.operands[0], Offset) # SFTODO TEMP?
    print("%s" % (self.operands[0]))


def dump_case_block(self, rld): # SFTODO RENAME SELF
    acme_dump_case_block(self.opcode, self.operands) # SFTODO FOLD INTO HERE?



def disassemble_branch(disassembly_info, i):
    opcode = disassembly_info.labelled_blob[i]
    # SFTODO: Validate opcode?? Arguably redundant given how this is called
    offset, i = Offset.disassemble(disassembly_info, i+1)
    return Instruction(opcode, [offset]), i

def dump_branch(self, rld): # SFTODO RENAME FIRST ARG
    # SFTODO: Fold acme_dump_branch() in here? Also used in SelInstruction tho...
    acme_dump_branch(self.opcode, self.operands)


def disassemble_sel(di, i):
    i += 1
    di.special[i + di.labelled_blob.read_u16(i)] = True
    offset, i = Offset.disassemble(di, i)
    return Instruction('SEL', [offset]), i

def dump_sel(self, rld):
    # SFTODO: Fold acme_dump_branch() in here?
    acme_dump_branch(self.opcode, self.operands)



# SFTODO: Perhaps rename this ImpliedInstruction? I use it for things like RET which don't really use the stack as such, but are similar in the sense that the data (if any) is implied, not explicit.
def disassemble_stack_instruction(disassembly_info, i):
    opcode = disassembly_info.labelled_blob[i]
    # SFTODO: Validate opcode?? Arguably redundant given how this is called
    return Instruction(opcode, []), i+1

def dump_stack_instruction(self, rld): # SFTODO: RENAME SELF
    print("\t!BYTE\t$%02X\t\t\t; %s" % (self.opcode, opdict[self.opcode]['opcode']))



def disassemble_immediate_instruction(disassembly_info, i, operand_count):
    opcode = disassembly_info.labelled_blob[i]
    # SFTODO: Validate opcode?? Arguably redundant given how this is called
    i += 1
    operands = []
    for j in range(operand_count):
        operand, i = Byte.disassemble(disassembly_info, i)
        operands.append(operand)
    return Instruction(opcode, operands), i

def disassemble_immediate_instruction1(disassembly_info, i):
    return disassemble_immediate_instruction(disassembly_info, i, 1)

def disassemble_immediate_instruction2(disassembly_info, i):
    return disassemble_immediate_instruction(disassembly_info, i, 2)

def dump_immediate_instruction(self, rld): # SFTODO: RENAME SELF
    if len(self.operands) == 1:
        print("\t!BYTE\t$%02X,$%02X\t\t\t; %s\t%s" % (self.opcode, self.operands[0].value, opdict[self.opcode]['opcode'], self.operands[0].value))
    elif len(self.operands) == 2:
        print("\t!BYTE\t$%02X,$%02X,$%02X\t\t; %s\t%s,%s" % (self.opcode, self.operands[0].value, self.operands[1].value, opdict[self.opcode]['opcode'], self.operands[0].value, self.operands[1].value))
    else:
        assert False


# TODO: partly by analogy with 6502 instruction terminology
# TODO: MemoryInstruction -> AbsoluteInstruction
# TODO: StackInstruction -> ImpliedInstruction

def disassemble_absolute_instruction(disassembly_info, i):
    opcode = disassembly_info.labelled_blob[i]
    # SFTODO: Validate opcode?? Arguably redundant given how this is called
    i += 1
    address, i = AbsoluteAddress.disassemble(disassembly_info, i)
    return Instruction(opcode, [address]), i

def dump_absolute_instruction(self, rld): # SFTODO RENAME SELF
    # SFTODO: Probably merge acme_dump_label in here - actually we probably need to rename it now, since it is actually dumping a Label or ExternalReference or FixedAddress (I think; check)
    acme_dump_label(self.opcode, self.operands, rld)



def disassemble_frame_instruction(disassembly_info, i):
    opcode = disassembly_info.labelled_blob[i]
    # TODO: I think FrameOffset probably adds very little and we should just use a raw int here, but let's not try to get rid of it just yet - OK, I am now thinking it does have value, since memory() returns a set of addresses and these can be mixed together from various instructions, so having a 'type' is handy
    frame_offset = FrameOffset(disassembly_info.labelled_blob[i+1])
    return Instruction(opcode, [frame_offset]), i+2

def dump_frame_instruction(self, rld): # SFTODO RENAME SELF
    print("\t!BYTE\t$%02X,$%02X\t\t\t; %s\t[%s]" % (self.opcode, self.operands[0].value, opdict[self.opcode]['opcode'], self.operands[0].value))



def disassemble_string_instruction(disassembly_info, i):
    s, i = String.disassemble(disassembly_info, i+1)
    return Instruction(0x2e, [s]), i

def dump_string_instruction(self, rld): # SFTODO RENAME SELF
    # SFTODO: Fold acme_dump_cs in here
    acme_dump_cs(self.opcode, self.operands)



# SFTODO: Permanent comment if this lives and if I have the idea right - we are kind of implementing our own vtable here, which sucks a bit, but by doing this we can allow an Instruction object to be updated in-place to changes it opcode, which isn't possible if we use actual Python inheritance as the object's type can be changed. I am hoping that this will allow optimisations to be written more naturally, since it will be possible to change an instruction (which will work via standard for instruction in list stuff) rather than having to replace it (which requires forcing the use of indexes into the list so we can do ops[i] = NewInstruction())
instruction_class_fns = {
        InstructionClass.NOP: {'operands': 0},
        InstructionClass.LOCAL_LABEL: {'dump': dump_local_label, 'operands': 1, 'operand_type': Offset},
        InstructionClass.CONSTANT: {'disassemble': disassemble_constant, 'dump': dump_constant, 'operands': 1, 'operand_type': int},
        InstructionClass.BRANCH: {'disassemble': disassemble_branch, 'dump': dump_branch, 'operands': 1, 'operand_type': Offset},
        InstructionClass.STACK: {'disassemble': disassemble_stack_instruction, 'dump': dump_stack_instruction, 'operands': 0},
        InstructionClass.IMMEDIATE1: {'disassemble': disassemble_immediate_instruction1, 'dump': dump_immediate_instruction, 'operands': 1, 'operand_type': Byte},
        InstructionClass.IMMEDIATE2: {'disassemble': disassemble_immediate_instruction2, 'dump': dump_immediate_instruction, 'operands': 2, 'operand_type': Byte},
        InstructionClass.ABSOLUTE: {'disassemble': disassemble_absolute_instruction, 'dump': dump_absolute_instruction, 'operands': 1, 'operand_type': AbsoluteAddress},
        InstructionClass.FRAME: {'disassemble': disassemble_frame_instruction, 'dump': dump_frame_instruction, 'operands': 1, 'operand_type': FrameOffset},
        InstructionClass.STRING: {'disassemble': disassemble_string_instruction, 'dump': dump_string_instruction, 'operands': 1, 'operand_type': String},
        InstructionClass.SEL: {'disassemble': disassemble_sel, 'dump': dump_sel, 'operands': 1, 'operand_type': Offset},
        InstructionClass.CASE_BLOCK: {'dump': dump_case_block, 'operands': 1, 'operand_type': CaseBlock},
}

# TODO: Check this table is complete and correct
# TODO: I do wonder if we'd go wrong if we actually had something like '*$3000=42' in a PLASMA program; we seem to be assuming that the operand of some opcodes is always a label, when it *might* be a literal
# TODO: I suspect I won't want most of the things in here eventually, but for now I am avoiding removing anything and just adding stuff. Review this later and get rid of unwanted stuff.
opdict = {
    0x00: {'opcode': 'CN', 'class': InstructionClass.CONSTANT},
    0x02: {'opcode': 'CN', 'class': InstructionClass.CONSTANT},
    0x04: {'opcode': 'CN', 'class': InstructionClass.CONSTANT},
    0x06: {'opcode': 'CN', 'class': InstructionClass.CONSTANT},
    0x08: {'opcode': 'CN', 'class': InstructionClass.CONSTANT},
    0x0a: {'opcode': 'CN', 'class': InstructionClass.CONSTANT},
    0x0c: {'opcode': 'CN', 'class': InstructionClass.CONSTANT},
    0x0e: {'opcode': 'CN', 'class': InstructionClass.CONSTANT},
    0x10: {'opcode': 'CN', 'class': InstructionClass.CONSTANT},
    0x12: {'opcode': 'CN', 'class': InstructionClass.CONSTANT},
    0x14: {'opcode': 'CN', 'class': InstructionClass.CONSTANT},
    0x16: {'opcode': 'CN', 'class': InstructionClass.CONSTANT},
    0x18: {'opcode': 'CN', 'class': InstructionClass.CONSTANT},
    0x1a: {'opcode': 'CN', 'class': InstructionClass.CONSTANT},
    0x1c: {'opcode': 'CN', 'class': InstructionClass.CONSTANT},
    0x1e: {'opcode': 'CN', 'class': InstructionClass.CONSTANT},
    0x20: {'opcode': 'MINUS1', 'class': InstructionClass.CONSTANT},
    0x22: {'opcode': 'BREQ', 'class': InstructionClass.BRANCH},
    0x24: {'opcode': 'BRNE', 'class': InstructionClass.BRANCH},
    0x26: {'opcode': 'LA', 'class': InstructionClass.ABSOLUTE},
    0x28: {'opcode': 'LLA', 'class': InstructionClass.FRAME},
    0x2a: {'opcode': 'CB', 'class': InstructionClass.CONSTANT},
    0x2c: {'opcode': 'CW', 'class': InstructionClass.CONSTANT},
    0x2e: {'opcode': 'CS', 'class': InstructionClass.STRING},
    0x30: {'opcode': 'DROP', 'class': InstructionClass.STACK},
    0x32: {'opcode': 'DROP2', 'class': InstructionClass.STACK},
    0x34: {'opcode': 'DUP', 'class': InstructionClass.STACK},
    0x38: {'opcode': 'ADDI', 'class': InstructionClass.IMMEDIATE1},
    0x3a: {'opcode': 'SUBI', 'class': InstructionClass.IMMEDIATE1},
    0x3c: {'opcode': 'ANDI', 'class': InstructionClass.IMMEDIATE1},
    0x3e: {'opcode': 'ORI', 'class': InstructionClass.IMMEDIATE1},
    0x40: {'opcode': 'ISEQ', 'class': InstructionClass.STACK},
    0x42: {'opcode': 'ISNE', 'class': InstructionClass.STACK},
    0x44: {'opcode': 'ISGT', 'class': InstructionClass.STACK},
    0x46: {'opcode': 'ISLT', 'class': InstructionClass.STACK},
    0x48: {'opcode': 'ISGE', 'class': InstructionClass.STACK},
    0x4a: {'opcode': 'ISLE', 'class': InstructionClass.STACK},
    0x4c: {'opcode': 'BRFLS', 'class': InstructionClass.BRANCH},
    0x4e: {'opcode': 'BRTRU', 'class': InstructionClass.BRANCH},
    0x50: {'opcode': 'BRNCH', 'class': InstructionClass.BRANCH, 'nis': True},
    0x52: {'opcode': 'SEL', 'class': InstructionClass.SEL},
    0x54: {'opcode': 'CALL', 'class': InstructionClass.ABSOLUTE}, # SFTODO: MemoryInstruction isn't necessarily best class here, but let's try it for now
    0x56: {'opcode': 'ICAL', 'class': InstructionClass.STACK},
    0x58: {'opcode': 'ENTER', 'class': InstructionClass.IMMEDIATE2},
    0x5c: {'opcode': 'RET', 'nis': True, 'class': InstructionClass.STACK},
    0x5a: {'opcode': 'LEAVE', 'nis': True, 'class': InstructionClass.IMMEDIATE1},
    0x5e: {'opcode': 'CFFB', 'class': InstructionClass.CONSTANT},
    0x60: {'opcode': 'LB', 'is_load': True, 'class': InstructionClass.STACK},
    0x62: {'opcode': 'LW', 'is_load': True, 'class': InstructionClass.STACK},
    0x64: {'opcode': 'LLB', 'is_load': True, 'data_size': 1, 'class': InstructionClass.FRAME},
    0x66: {'opcode': 'LLW', 'is_load': True, 'data_size': 2, 'class': InstructionClass.FRAME},
    0x68: {'opcode': 'LAB', 'is_load': True, 'data_size': 1, 'class': InstructionClass.ABSOLUTE},
    0x6a: {'opcode': 'LAW', 'is_load': True, 'data_size': 2, 'class': InstructionClass.ABSOLUTE},
    0x6c: {'opcode': 'DLB', 'is_dup_store': True, 'data_size': 1, 'class': InstructionClass.FRAME},
    0x6e: {'opcode': 'DLW', 'is_dup_store': True, 'data_size': 2, 'class': InstructionClass.FRAME},
    0x70: {'opcode': 'SB', 'is_store': True, 'class': InstructionClass.STACK},
    0x72: {'opcode': 'SW', 'is_store': True, 'class': InstructionClass.STACK},
    0x74: {'opcode': 'SLB', 'is_store': True, 'data_size': 1, 'class': InstructionClass.FRAME},
    0x76: {'opcode': 'SLW', 'is_store': True, 'data_size': 2, 'class': InstructionClass.FRAME},
    0x78: {'opcode': 'SAB', 'is_store': True, 'data_size': 1, 'class': InstructionClass.ABSOLUTE},
    0x7a: {'opcode': 'SAW', 'is_store': True, 'data_size': 2, 'class': InstructionClass.ABSOLUTE},
    0x7c: {'opcode': 'DAB', 'is_dup_store': True, 'data_size': 1, 'class': InstructionClass.ABSOLUTE},
    0x7e: {'opcode': 'DAW', 'is_dup_store': True, 'data_size': 2, 'class': InstructionClass.ABSOLUTE},
    0x80: {'opcode': 'LNOT', 'class': InstructionClass.STACK},
    0x82: {'opcode': 'ADD', 'class': InstructionClass.STACK},
    0x84: {'opcode': 'SUB', 'class': InstructionClass.STACK},
    0x86: {'opcode': 'MUL', 'class': InstructionClass.STACK},
    0x88: {'opcode': 'DIV', 'class': InstructionClass.STACK},
    0x8a: {'opcode': 'MOD', 'class': InstructionClass.STACK},
    0x8c: {'opcode': 'INCR', 'class': InstructionClass.STACK},
    0x8e: {'opcode': 'DECR', 'class': InstructionClass.STACK},
    0x90: {'opcode': 'NEG', 'class': InstructionClass.STACK},
    0x92: {'opcode': 'COMP', 'class': InstructionClass.STACK},
    0x94: {'opcode': 'BAND', 'class': InstructionClass.STACK},
    0x96: {'opcode': 'IOR', 'class': InstructionClass.STACK},
    0x98: {'opcode': 'XOR', 'class': InstructionClass.STACK},
    0x9a: {'opcode': 'SHL', 'class': InstructionClass.STACK},
    0x9c: {'opcode': 'SHR', 'class': InstructionClass.STACK},
    0x9e: {'opcode': 'IDXW', 'class': InstructionClass.STACK},
    0xa0: {'opcode': 'BRGT', 'class': InstructionClass.BRANCH},
    0xa2: {'opcode': 'BRLT', 'class': InstructionClass.BRANCH},
    0xa4: {'opcode': 'INCBRLE', 'class': InstructionClass.BRANCH},
    0xa8: {'opcode': 'DECBRGE', 'class': InstructionClass.BRANCH},
    0xac: {'opcode': 'BRAND', 'class': InstructionClass.BRANCH},
    0xae: {'opcode': 'BROR', 'class': InstructionClass.BRANCH},
    0xb0: {'opcode': 'ADDLB', 'is_load': True, 'data_size': 1, 'class': InstructionClass.FRAME},
    0xb2: {'opcode': 'ADDLW', 'is_load': True, 'data_size': 2, 'class': InstructionClass.FRAME},
    0xb4: {'opcode': 'ADDAB', 'is_load': True, 'data_size': 1, 'class': InstructionClass.ABSOLUTE},
    0xb6: {'opcode': 'ADDAW', 'is_load': True, 'data_size': 2, 'class': InstructionClass.ABSOLUTE},
    0xb8: {'opcode': 'IDXLB', 'is_load': True, 'data_size': 1, 'class': InstructionClass.FRAME},
    0xba: {'opcode': 'IDXLW', 'is_load': True, 'data_size': 2, 'class': InstructionClass.FRAME},
    0xbc: {'opcode': 'IDXAB', 'is_load': True, 'data_size': 1, 'class': InstructionClass.ABSOLUTE},
    0xbe: {'opcode': 'IDXAW', 'is_load': True, 'data_size': 2, 'class': InstructionClass.ABSOLUTE},
    CONSTANT_OPCODE: {'pseudo': True, 'class': InstructionClass.CONSTANT},
    LOCAL_LABEL_OPCODE: {'pseudo': True, 'class': InstructionClass.LOCAL_LABEL},
    NOP_OPCODE: {'pseudo': True, 'class': InstructionClass.NOP},
    CASE_BLOCK_OPCODE: {'pseudo': True, 'class': InstructionClass.CASE_BLOCK},
}

opcode = {v['opcode']: k for (k, v) in opdict.items() if not v.get('pseudo', False)}

class BytecodeFunction(object):
    def __init__(self, labelled_blob):
        assert isinstance(labelled_blob, LabelledBlob)
        self.labels = labelled_blob.labels[0]
        for label in self.labels:
            label.set_owner(self)
        self.ops = [] # SFTODO Should perhaps call 'instructions'
        di = DisassemblyInfo(self, labelled_blob)

        i = 0
        while i < len(labelled_blob):
            # There should be no labels within a bytecode function. We will later
            # create branch-target labels based on the branch instructions within
            # the function, but those are different.
            assert i == 0 or not labelled_blob.labels[i]
            for t in di.local_target[i]:
                self.ops.append(Instruction(LOCAL_LABEL_OPCODE, [t]))
                di.op_offset.append(None)
            di.op_offset.append(i) # SFTODO SHOULD WE DO THIS EVEN IF SPECIAL?
            special = di.special[i]
            if not special:
                opcode = labelled_blob[i]
                #print('SFTODOQQ %X' % opcode)
                opdef = opdict[opcode]
                assert not opdef.get('pseudo')
                dis = instruction_class_fns[opdef['class']]['disassemble']
                op, i = dis(di, i)
            else:
                operand, i = CaseBlock.disassemble(di, i)
                op = Instruction(CASE_BLOCK_OPCODE, [operand])
            self.ops.append(op)

    def is_init(self):
        return any(x.name == '_INIT' for x in self.labels)

    def update_used_things(self, used_things):
        if self in used_things:
            return
        used_things.add(self)
        for instruction in self.ops:
            instruction.update_used_things(used_things)

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


# Remove a BRNCH to an immediately following label.
def branch_optimise(bytecode_function):
    changed = False
    new_ops = []
    for i, instruction in enumerate(bytecode_function.ops):
        next_instruction = None if i == len(bytecode_function.ops)-1 else bytecode_function.ops[i+1]
        if not (instruction.is_a('BRNCH') and next_instruction and next_instruction.is_local_label() and instruction.operands[0] == next_instruction.operands[0]):
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
# TODO: Not just in this function - I am a bit inconsistent with opcode meaning "BRNCH" and opcode meaning 0x50 - perhaps check terminology, but I think opcode should be a hex value (so the opcode reverse dict is fine, because it gives us the opcode for a name, it's the 'opcode' member of the subdicts in opdict that are wrong, among others)
def branch_optimise2(bytecode_function):
    changed = False
    targets = build_local_label_dictionary(bytecode_function, lambda instruction: instruction.is_a('LEAVE', 'RET'))
    for instruction in bytecode_function.ops:
        if instruction.is_a('BRNCH'):
            target = targets.get(instruction.operands[0])
            if target:
                instruction.set(target)
                changed = True
    return changed

# If we have any kind of branch whose target is a BRNCH, replace the first branch's target with the
# BRNCH's target (i.e. just branch directly to the final destination in the first branch).
def branch_optimise3(bytecode_function):
    changed = False
    targets = build_local_label_dictionary(bytecode_function, lambda instruction: instruction.is_a('BRNCH'))
    alias = {k:v.operands[0] for k, v in targets.items()}
    for instruction in bytecode_function.ops:
        original_operands = instruction.operands[:] # SFTODO EXPERIMENTAL - THIS IS NOW WORKING, BUT I'D RATHER NOT HAVE TO DO THIS
        instruction.rename_local_labels(alias)
        changed = changed or (original_operands != instruction.operands)
    return changed

# Remove local labels which have no instructions referencing them; this can occur as a result
# of other optimisations and is useful in opening up further optimisations.
def remove_orphaned_labels(bytecode_function):
    changed = False
    labels_used = set()
    for instruction in bytecode_function.ops:
        instruction.update_local_labels_used(labels_used)
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
    # This works in conjunction with remove_orphaned_labels().
    def get_blocks(bytecode_function): # SFTODO: Don't like name clash with global get_blocks(), rename this
        foo = Foo(bytecode_function)
        foo.start_before(0, True)
        for i, instruction in enumerate(bytecode_function.ops):
            if never_immediate_successor(instruction.opcode):
                foo.start_after(i, None)
            elif instruction.is_local_label():
                foo.start_before(i, True)
        return foo.get_blocks_and_metadata()

    blocks, block_reachable = get_blocks(bytecode_function)
    bytecode_function.ops = list(itertools.chain.from_iterable(itertools.compress(blocks, block_reachable)))
    return not all(block_reachable)

# A CASEBLOCK instruction is followed by the 'otherwise' instructions. If the 'otherwise'
# instructions end with a terminator, the CASEBLOCK+otherwise instructions form an isolated
# block which can be moved around freely. If such a block is preceded by a BRNCH, we move it
# to the end of the function - this may allow the BRNCH to be optimised away. (It would be
# correct and mostly harmless to move any isolated CASEBLOCK+otherwise instruction block to
# the end of the function, but it would introduce unnecessary differences between the input
# and output.)
def move_case_blocks(bytecode_function):
    blocks, block_label = get_blocks(bytecode_function)
    new_ops = []
    tail = []
    for i, block in enumerate(blocks):
        if block_label[i] and len(block) > 1 and block[1].opcode == CASE_BLOCK_OPCODE and never_immediate_successor(block[-1].opcode) and blocks[i-1][-1].is_a('BRNCH'):
            tail.extend(block)
        else:
            new_ops.extend(block)
    new_ops.extend(tail)
    changed = bytecode_function.ops != new_ops 
    bytecode_function.ops = new_ops
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
    # harder to verify the transformations performed by this function are valid), we remove any
    # redundant branches to the immediately following instruction first.
    changed = branch_optimise(bytecode_function)

    blocks, blocks_metadata, block_label_only = get_blocks2(bytecode_function)

    # Merge blocks where possible.
    for i, block in enumerate(blocks):
        if block and block[-1].is_a('BRNCH'):
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


# SFTODO TEMPORARY (?) PSEUDO-CTOR FOR TRANSITION
def NopInstruction():
    return Instruction(NOP_OPCODE, [])


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
        if i > 0 and instruction.is_a('BRNCH'):
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
            labels_used = set()
            instruction.update_local_labels_used(labels_used)
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
            if i > 0 and instruction.is_a('BRNCH'):
                label = instruction.operands[0]
                if label in candidates:
                    candidate = candidates[label]
                    if candidate:
                        new_ops[i-1] = NopInstruction()
            i += 1
        bytecode_function.ops = [op for op in new_ops if op.opcode != NOP_OPCODE]

    return changed

# Used to test for an unlikely case when optimising things like "LLW [n]:SLW [m]:LLW [n]" to
# "LLW [n]:DLW [m]". If m=n this optimisation is valid, but if m=n+1 the final LLW [n] is
# loading a different value than the first and the optimisation cannot be performed.
def partial_overlap(lhs, rhs): # SFTODO: RENAME TO REMOVE no_ PREFIX?
    lhs_memory = lhs.memory()
    rhs_memory = rhs.memory()
    return lhs_memory != rhs_memory and len(lhs_memory.intersection(rhs_memory)) > 0



def peephole_optimise(bytecode_function):
    changed = False
    i = 0
    bytecode_function.ops += [NopInstruction(), NopInstruction()] # add dummy NOPs so we can use ops[i+2] freely
    while i < len(bytecode_function.ops)-2:
        instruction = bytecode_function.ops[i]
        next_instruction = bytecode_function.ops[i+1]
        next_next_instruction = bytecode_function.ops[i+2]
        # DROP:DROP -> DROP2
        if instruction.is_a('DROP') and next_instruction.is_a('DROP'):
            bytecode_function.ops[i] = Instruction('DROP2')
            bytecode_function.ops[i+1] = NopInstruction()
            changed = True
        # BRTRU x:BRNCH y:x -> BRFLS y:x (and similar)
        elif instruction.is_conditional_branch() and next_instruction.is_a('BRNCH') and next_next_instruction.is_local_label() and instruction.operands[0] == next_next_instruction.operands[0]:
            bytecode_function.ops[i].invert_condition()
            bytecode_function.ops[i].operands = next_instruction.operands
            bytecode_function.ops[i+1] = NopInstruction()
            changed = True
        elif instruction.is_simple_store() and not instruction.has_side_effects() and next_instruction.is_simple_load() and not next_instruction.has_side_effects() and instruction.operands[0] == next_instruction.operands[0] and instruction.data_size() == next_instruction.data_size():
            dup_for_store = {0x7a: 0x7e, # SFTODO MAGIC CONSTANTS
                             0x78: 0x7c,
                             0x74: 0x6c,
                             0x76: 0x6e}
            bytecode_function.ops[i] = Instruction(dup_for_store[instruction.opcode], instruction.operands)
            bytecode_function.ops[i+1] = NopInstruction()
            changed = True
        # "LLW [n]:SAW x:LLW [n]" -> "LLW [n]:DAW x" and variations
        # SFTODO: I am using has_side_effects() as a kind of placeholder for "might access memory-mapped I/O" here
        elif instruction.is_simple_load() and instruction == next_next_instruction and next_instruction.is_simple_store() and not instruction.has_side_effects() and not next_instruction.has_side_effects() and not partial_overlap(instruction, next_instruction):
            dup_for_store = {0x7a: 0x7e, # SFTODO MAGIC CONSTANTS, COPY AND PASTE
                             0x78: 0x7c,
                             0x74: 0x6c,
                             0x76: 0x6e}
            bytecode_function.ops[i+1] = Instruction(dup_for_store[next_instruction.opcode], next_instruction.operands)
            bytecode_function.ops[i+2] = NopInstruction()
            changed = True
        elif instruction.is_simple_stack_push() and next_instruction.is_a('DROP'):
            # SFTODO: We should probably recognise the case where we have two 'simple stack pushes' foillowed by DROP2. Maybe we should expand DROP2 opcodes into DROP:DROP very early on, and only as a final pass revert this - that might help keep things "transparent" to the optimiser.
            bytecode_function.ops[i] = NopInstruction()
            bytecode_function.ops[i+1] = NopInstruction()

        i += 1
    bytecode_function.ops = bytecode_function.ops[:-2] # remove dummy NOP
    changed = changed or any(op.opcode == NOP_OPCODE for op in bytecode_function.ops)
    bytecode_function.ops = [op for op in bytecode_function.ops if op.opcode != NOP_OPCODE]
    return changed








def is_branch_or_label(instruction):
    # TODO: THIS MAY NEED TO BE CONFIGURABLE TO DECIDE WHETHER CALL OR ICAL COUNT AS BRANCHES - TBH straightline_optimise() MAY BE BETTER RECAST AS A UTILITY TO BE CALLED BY AN OPTIMISATION FUNCTION NOT SOMETHIG WHICH CALLS OPTIMISATION FUNCTIONS
    return instruction.is_local_label() or instruction.is_branch()

def get_straightline_blocks(bytecode_function):
    foo = Foo(bytecode_function)
    for i, instruction in enumerate(bytecode_function.ops):
        if i == 0 or is_branch_or_label(instruction) != is_branch_or_label(bytecode_function.ops[i-1]):
            foo.start_before(i, not is_branch_or_label(instruction))
    return foo.get_blocks_and_metadata()

def straightline_optimise(bytecode_function, optimisations):
    blocks, is_straightline_block = get_straightline_blocks(bytecode_function)
    changed = False
    new_ops = []
    for block, is_straightline in zip(blocks, is_straightline_block):
        if is_straightline:
            for optimisation in optimisations:
                # optimisation function may modify block in place if it wishes, but it
                # may also be more convenient for it to create a new list so we take a
                # return value; it can of course just 'return block' if it does everything
                # in place.
                block, changed2 = optimisation(bytecode_function, block)
                changed = changed or changed2
        new_ops.extend(block)
    bytecode_function.ops = new_ops
    return changed

# Within a bytecode function, we have to assume that any frame offset >= that used by an
# LLA opcode can be accessed indirectly through the address returned by LLA, e.g. by a
# function call or LB/SB. If we knew how big the frame object referenced by the LLA was,
# we could set an upper bound, but we don't have that information. (This assumes that
# it's not valid to rely on the order in which the compiler allocates frame objects and
# access the "preceding" object using a negative offer on the LLA result; I don't think
# this is an unreasonable assumption.)
def calculate_lla_threshold(bytecode_function):
    lla_threshold = 256
    for instruction in bytecode_function.ops:
        if instruction.is_a('LLA'):
            lla_threshold = min(instruction.operands[0].value, lla_threshold)
    return lla_threshold


# TODO: This optimisation will increase expression stack usage, which might break some
# programs - it should probably be controlled separately (e.g. -O3 only, and/or a
# --risky-optimisations switch). It currently has no effect, as in the self-hosted
# compiler all the code it touched is preferentially improved by peephole_optimise().
# If this is retained, we need to be *sure* that it doesn't kick in first, as it can
# prevent that superior optimisation. I think in general introducing DUP "complicates"
# the code from an optimisation POV, so we want to do anything which might introduce
# them only when every other optimisation has failed to change anything. (Then of course
# we can do a pass round the whole set of optimisations again.)
def load_to_dup(bytecode_function, straightline_ops):
    changed = False
    for i in range(len(straightline_ops)):
        instruction = straightline_ops[i]
        if instruction.is_simple_load() and not instruction.has_side_effects():
            stores_access = set()
            j = i + 1
            while j < len(straightline_ops):
                if straightline_ops[j].is_simple_store() or straightline_ops[i].is_dup_store():
                    stores_access.update(straightline_ops[j].memory())
                    if straightline_ops[j].is_simple_store():
                        j += 1
                        break
                else:
                    break
                j += 1
            if j < len(straightline_ops) and instruction == straightline_ops[j]:
                # We have a load, zero or more "dup stores", a store and an identical load.
                # Provided none of the intervening stores modify the data loaded and the
                # load has no side effects, we can replace the initial load with a load:DUP
                # and remove the final load.  SFTODO: THIS IS STUPID, I THINK - WE SHOULD INSTEAD REPLACE THE STORE WITH A DUP STORE AND REMOVE THE FINAL LOAD - THIS IS (NEED TO RETHINK TO BE SURE) AN EXTENSION OF THE OPTIMISATION WE ALREADY HAVE IN PEEPHOLE_OPTIMISE
                loads_access = instruction.memory()
                if len(loads_access.intersection(stores_access)) == 0:
                    for k in range(j, i+1, -1):
                        straightline_ops[k] = straightline_ops[k-1]
                    # SFTODO: This code is obviously never exercised as I have removed StackInstruction...
                    straightline_ops[i+1] = Instruction('DUP')
                    changed = True

    return straightline_ops, changed


# bidict taken from Basj's answer at https://stackoverflow.com/questions/3318625/efficient-bidirectional-hash-table-in-python
class bidict(dict):
    def __init__(self, *args, **kwargs):
        super(bidict, self).__init__(*args, **kwargs)
        self.inverse = {}
        for key, value in self.iteritems():
            self.inverse.setdefault(value,[]).append(key) 

    def __setitem__(self, key, value):
        if key in self:
            self.inverse[self[key]].remove(key) 
        super(bidict, self).__setitem__(key, value)
        self.inverse.setdefault(value,[]).append(key)        

    def __delitem__(self, key):
        self.inverse.setdefault(self[key],[]).remove(key)
        if self[key] in self.inverse and not self.inverse[self[key]]: 
            del self.inverse[self[key]]
        super(bidict, self).__delitem__(key)


def is_hardware_address(address):
    # SFTODO: Again the 'address as generic term' and 'FixedAddress as an absolute address' awkwardness...
    # TODO: 0xc000 is a crude compromise for Acorn and Apple; might be nice to support a better
    # compromise (I note the self-hosted compiler's optimiser puts upper bound of 0xd000; this won't
    # work for Acorn, not that I have "ported" the optimiser yet) and perhaps offer a --platform
    # command line switch to trigger a tighter definition where platform is known.
    return isinstance(address, FixedAddress) and address.value >= 0xc000


# SFTODO: When I extend this to absolute loads/stores, I need to be careful not to optimise away memory mapped I/O. I *think* it's not possible for a Label or ExternalRef to refer to such memory (they always refer to compiler-allocated data) but need to document that in case it turns out I am wrong. Once I extend this tool to cope with the case (which doesn't occur in the self-hosted compiler, which is my current and only test case) of an actual absolute address (e.g. SAB &FFE0), it will need to be careful not to optimise away stores to such addresses.
def optimise_load_store(bytecode_function, straightline_ops):
    lla_threshold = calculate_lla_threshold(bytecode_function)

    # unobserved_stores is a bidirectional dictionary "memory address" <-> "store instruction
    # index"; it allows us to model the access to memory by straightline_ops to see if any stores
    # are provably redundant. Note that when 'del unobserved_stores[address]' removes the last
    # address associated with an instruction index, the instruction index is removed from the
    # inverse dictionary. On the other hand, if 'unobserved_stores[address] = i' replaces the last
    # address associated with an instruction index, an empty list remains in the inverse dictionary.
    # This allows us to distinguish the two cases; the former case indicates a store instruction
    # has had at least one of its effects observed, the latter indicates a store instruction had
    # no observable effect and can be removed.
    unobserved_stores = bidict()

    for i, instruction in enumerate(straightline_ops):
	is_store = instruction.is_simple_store() or instruction.is_dup_store()
	is_load = (instruction.is_load() and not instruction.is_a('LB', 'LW'))
        if is_store: # stores and duplicate-stores
            for address in instruction.memory():
                if not is_hardware_address(address):
                    unobserved_stores[address] = i
        elif is_load:
            for address in instruction.memory():
                if address in unobserved_stores:
                    del unobserved_stores[address]
        elif instruction.is_a('CALL', 'ICAL', 'LB', 'LW'):
            # We have to assume this may observe the value of anything except a frame offset
            # which hasn't been exposed via LLA.
            for address in unobserved_stores.keys():
                if not (isinstance(address, FrameOffset) and address.value < lla_threshold):
                    del unobserved_stores[address]
	elif instruction.is_a('RET', 'LEAVE'):
            # We're exiting the current function, so any unobserved stores to frame offsets
            # will never be observed. We model this by treating this instruction as doing
            # a store to each such offset. (LLA doesn't matter here; once this instruction
            # executes any pointer obtained by LLA points to deallocated memory.)
            for address in unobserved_stores.keys():
                if isinstance(address, FrameOffset):
                    unobserved_stores[address] = i

    changed = False
    for i, addresses in unobserved_stores.inverse.items():
        if len(addresses) == 0:
            store_instruction = straightline_ops[i]
            assert store_instruction.is_simple_store() or store_instruction.is_dup_store()
            if store_instruction.is_dup_store():
                straightline_ops[i] = NopInstruction()
            else:
                straightline_ops[i] = Instruction('DROP')
            changed = True

    return [op for op in straightline_ops if not op.instruction_class == InstructionClass.NOP], changed



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

assert new_module.bytecode_functions[-1].is_init()
used_things = set()
new_module.bytecode_functions[-1].update_used_things(used_things)
for external_name, reference in new_esd.entry_dict.items():
    reference.update_used_things(used_things)
#print('SFTODOXXX %r', used_things)
#print('SFTODOXXX %r', len(used_things))
# We preserve the order of things in the input module; this automatically ensure that
# the data/asm blob comes first and init comes last, and it also avoids gratuitous
# reordering which makes comparing the input and output difficult.
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
for bytecode_function in used_things_ordered:
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
                result.append(move_case_blocks(bytecode_function))
                assert SFTODO(bytecode_function.ops)
                result.append(peephole_optimise(bytecode_function))
                assert SFTODO(bytecode_function.ops)
                result.append(straightline_optimise(bytecode_function, [optimise_load_store, load_to_dup]))
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
defcnt = len(used_things_ordered)

print("_DEFCNT = %d" % (defcnt,))
print("_SEGEND")
print(";\n; RE-LOCATEABLE DICTIONARY\n;")

new_rld.dump()

new_esd.dump()

# TODO: Would it be worth replacing "CN 1:SHL" with "DUP:ADD"? This occurs in the self-hosted compiler at least once. It's the same length, so would need to cycle count to see if it's faster.

# TODO: Perhaps not worth it, and this is a space-not-speed optimisation, but if it's common to CALL a function FOO and then immediately do a DROP afterwards (across all code in the module, not just one function), it may be a space-saving win to generate a function FOO-PRIME which does "(no ENTER):CALL FOO:DROP:RET" and replace CALL FOO:DROP with CALL FOO-PRIME. We could potentially generalise this (we couldn't do it over multiple passes) to recognising the longest common sequence of operations occurring after all CALLs to FOO and factoring them all into FOO-PRIME.

# TODO: Just possibly we should expand DUP if the preceding instruction is a simple_stack_push
# early in the optimisation to make the effects more obvious, and have a final DUP-ification pass which will revert this change where there is still value in the DUP - this might enable other optimisations in the meantime - but it may also make things worse
