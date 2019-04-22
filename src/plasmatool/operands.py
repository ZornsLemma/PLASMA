from __future__ import print_function

import collections

from utils import *



class Byte(ComparisonMixin):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return "%d" % (self.value,)

    def __repr__(self):
        return "Byte(%d)" % (self.value,)

    def keys(self):
        return (self.value,)


class FrameOffset(Byte):
    def __add__(self, rhs):
        assert isinstance(rhs, int)
        return FrameOffset(self.value + rhs)

class Target(ComparisonMixin):
    """Class representing a branch target within a bytecode function; these could also be
       called (local) labels, but we use this distinct name to distinguish them from Label
       objects, which exist at the module level."""

    _next = 0

    def __init__(self, value=None):
        if not value:
            value = '_L%04d' % (Target._next,)
            Target._next += 1
        assert isinstance(value, str)
        object.__setattr__(self, "_value", value) # avoid using our throwing __setattr__()

    def __setattr__(self, *args):
        # The same Target object is likely shared by multiple instructions, both TARGET
        # pseudo-instructions which define its location and branch instructions which
        # reference it. Accidentally modifying a Target object in place rather than
        # replacing it with a different Target object will therefore affect more than just
        # the instruction we intended to modify, so we go out of our way to prevent this.
        raise TypeError("Target is immutable")

    def __str__(self):
        return self._value

    def __repr__(self):
        return "Target(%s)" % (self._value,)

    def keys(self):
        return (self._value,)

    def replace_targets(self, alias):
        raise TypeError("Target is immutable") # use non-member replace_targets() instead

    def add_targets_used(self, targets_used):
        targets_used.add(self)

    @classmethod
    def disassemble(cls, di, i):
        target_pos = i + sign_extend(di.labelled_blob.read_u16(i))
        target = Target()
        di.target[target_pos].append(target)
        return target, i+2


class CaseBlock(ComparisonMixin):
    def __init__(self, table):
        self.table = table

    def __repr__(self):
        return "CaseBlock(%d)" % (len(self.table),)

    def keys(self):
        return (self.table,)

    def replace_targets(self, alias):
        for i, (value, target) in enumerate(self.table):
            self.table[i] = (self.table[i][0], replace_targets(self.table[i][1], alias))

    def add_targets_used(self, targets_used):
        for value, target in self.table:
            target.add_targets_used(targets_used)

    @classmethod
    def disassemble(cls, di, i):
        count = di.labelled_blob[i]
        table = []
        for j in range(count):
            k = i + 1 + 4*j
            value = di.labelled_blob.read_u16(k)
            target, _ = Target.disassemble(di, k+2)
            table.append((value, target))
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



class AbsoluteAddress(object):
    """Base class for operands which represent an absolute memory address, although not
       necessarily one which is known before the module is loaded into the VM."""

    @classmethod
    def disassemble(cls, di, i):
        address = di.labelled_blob.references.get(i)
        if address:
            assert isinstance(address, Label) or isinstance(address, ExternalReference)
            return address, i+2
        else:
            return FixedAddress.disassemble(di, i)


class Label(AbsoluteAddress, ComparisonMixin):
    _next = collections.defaultdict(int)

    def __init__(self, prefix, add_suffix = True):
        # We don't need to populate self.owner here; we are either creating a Label object
        # to be initially associated with the single LabelledBlob corresponding to the whole
        # input module, which will be sliced up later on, or we are creating Label objects
        # only as part of dump() in which case no one cares about ownership.
        self.owner = None

        if add_suffix:
            i = Label._next[prefix]
            self.name = '%s%04d' % (prefix, i)
            Label._next[prefix] += 1
        else:
            self.name = prefix

    def keys(self):
        return (self.name,)

    def set_owner(self, owner):
        self.owner = owner

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

    def acme_reference(self, comment=True):
        return "!WORD\t%s" % (self.name,)

    def acme_rld(self, fixup_label, esd):
        return ("\t!BYTE\t$81\t\t\t; INTERNAL FIXUP\n" +
                "\t!WORD\t%s-_SEGBEGIN\n" +
                "\t!BYTE\t$00") % (fixup_label.name,)

    def acme_def(self, fixup_label):
        return ("\t!BYTE\t$02\t\t\t; CODE TABLE FIXUP\n" +
                "\t!WORD\t%s\n" +
                "\t!BYTE\t$00") % (fixup_label.name,)

    def add_dependencies(self, dependencies):
        self.owner.add_dependencies(dependencies)

    # SFTODO: I really don't like having to pass opdict into this function but the way I'm
    # decomposing it into seperate modules seems to leave me no better option.
    def dump(self, outfile, opcode, rld, opdict):
        print("\t!BYTE\t$%02X\t\t\t; %s\t%s" % (opcode, opdict[opcode]['opcode'], self.name), file=outfile)
        acme_dump_fixup(outfile, rld, self, False) # no comment, previous line shows this info


class ExternalReference(AbsoluteAddress, ComparisonMixin):
    def __init__(self, external_name, offset):
        self.external_name = external_name
        self.offset = offset

    def keys(self):
        return (self.external_name, self.offset)

    def __add__(self, rhs):
        assert isinstance(rhs, int)
        return ExternalReference(self.external_name, self.offset + rhs)
        
    def _name(self):
        if self.offset:
            return "%s+%d" % (self.external_name, self.offset)
        else:
            return self.external_name

    def acme_reference(self, comment=True):
        if comment:
            return "!WORD\t%d\t\t\t; %s" % (self.offset, self._name())
        else:
            return "!WORD\t%d" % (self.offset,)

    def acme_rld(self, fixup_label, esd):
        return ("\t!BYTE\t$91\t\t\t; EXTERNAL FIXUP\n" +
                "\t!WORD\t%s-_SEGBEGIN\n" +
                "\t!BYTE\t%d\t\t\t; ESD INDEX (%s)") % (fixup_label.name, esd.get_external_index(self.external_name), self.external_name)

    def add_dependencies(self, dependencies):
        pass

    # SFTODO: I really don't like having to pass opdict into this function but the way I'm
    # decomposing it into seperate modules seems to leave me no better option.
    def dump(self, outfile, opcode, rld, opdict):
        print("\t!BYTE\t$%02X\t\t\t; %s\t%s" % (opcode, opdict[opcode]['opcode'], self._name()), file=outfile)
        acme_dump_fixup(outfile, rld, self, False) # no comment, previous line shows this info


class FixedAddress(AbsoluteAddress, ComparisonMixin):
    """Class representing an absolute address which is a fixed address specified in the
       code, not one determined by the VM at load time."""

    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return "FixedAddress($%04X)" % (self.value,)

    def keys(self):
        return (self.value,)

    def __add__(self, rhs):
        assert isinstance(rhs, int)
        return FixedAddress(self.value + rhs)

    def add_dependencies(self, dependencies):
        pass

    @classmethod
    def disassemble(cls, di, i):
        return FixedAddress(di.labelled_blob.read_u16(i)), i+2

    def dump(self, outfile, opcode, rld):
        value = self.value
        print("\t!BYTE\t$%02X,$%02X,$%02X\t\t; %s\t$%04X" % (opcode, value & 0xff, (value & 0xff00) >> 8, opdict[opcode]['opcode'], value), file=outfile)



# This can't be a member of Target because Target objects are shared and so must be immutable.
def replace_targets(target, alias):
    assert isinstance(target, Target)
    assert isinstance(alias, dict)
    assert all(isinstance(k, Target) and isinstance(v, Target) for k,v in alias.items())
    return Target(alias.get(target, target)._value)



# SFTODO: Seems wrong to have these random free functions

def acme_dump_fixup(outfile, rld, reference, comment=True):
    fixup_label = Label('_F')
    rld.add_fixup(reference, fixup_label)
    print('%s\t%s' % (fixup_label.name, reference.acme_reference(comment)), file=outfile)
