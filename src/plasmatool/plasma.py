from __future__ import print_function

import collections
import struct

from operands import *

class LabelledBlob(object):
    def __init__(self, blob, labels=None, references=None):
        self.blob = blob
        self.labels = labels if labels else {}
        self.references = references if references else {}
        for label_list in self.labels.values():
            for label in label_list:
                label.set_owner(self)

    def __getitem__(self, key):
        if isinstance(key, slice):
            start = key.start
            stop = key.stop
            assert key.step is None
            return LabelledBlob(
                self.blob[start:stop],
                {k-start: v for k, v in self.labels.items() if start<=k<stop},
                {k-start: v for k, v in self.references.items() if start<=k<=stop})
        else:
            return ord(self.blob[key])

    def __len__(self):
        return len(self.blob)

    def label(self, key, lbl):
        self.labels.setdefault(key, []).append(lbl)

    def label_or_get(self, key, prefix):
        if key not in self.labels:
            self.labels[key] = [Label(prefix)]
        return self.labels[key][0]

    def reference(self, key, reference):
        assert key not in self.references
        self.references[key] = reference 

    def read_u16(self, key):
        return self[key] | (self[key+1] << 8)

    def add_dependencies(self, dependencies):
        if self in dependencies:
            return
        dependencies.add(self)
        for reference in self.references.values():
            reference.add_dependencies(dependencies)

    def dump(self, outfile, rld):
        i = 0
        while i < len(self.blob):
            for label in self.labels.get(i, []):
                print('%s' % (label.name,), file=outfile)
            reference = self.references.get(i)
            if reference is None:
                print('\t!BYTE\t$%02X' % (self[i],), file=outfile)
            else:
                acme_dump_fixup(outfile, rld, reference)
                i += 1
                assert i not in self.labels
                assert i not in self.references
            i += 1




# TODO: At least temporarily while Instruction objects can be constructed directly during transition, I am not doing things like overriding is_target() in the relevant derived class, because it breaks when an actual base-class Instruction object is constructed
class Instruction(ComparisonMixin):
    conditional_branch_pairs = (0x22, 0x24, 0x4c, 0x4e, 0xa0, 0xa2)

    def __init__(self, opcode, operands = None):
        self.set(opcode, operands)

    # SFTODO: Very few actual uses of this - is this because this approach of allowing an instruction to be changed in-place isn't useful, or because I just haven't got round to tweaking all the code which could benefit from this so it no longer needs to use index-base loops?
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

    # operands is a property so we can validate the instruction whenever it is updated.

    @property
    def operands(self):
        return self._operands

    @operands.setter
    def operands(self, value):
        self._operands = value
        InstructionClass.validate_instruction(self)

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

    def is_target(self):
        return self.opcode == TARGET_OPCODE

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
        # TODO: I am probably missing some possible instructions here, but for now let's keep it simple
        return (self.is_simple_load() and not self.has_side_effects()) or self.instruction_class == InstructionClass.CONSTANT

    def is_terminator(self):
        # SFTODO: Is there a good reason this code is so different from is_store()/is_load()/etc?
        opdef = opdict.get(self.opcode, None)
        return opdef and opdef.get('terminator', False)



    def has_side_effects(self):
        if not (self.is_load() or self.is_store() or self.is_dup_store()):
            return False
        if self.instruction_class == InstructionClass.IMPLIED:
            # Loads/stores which take addresses from the stack could access any address,
            # so we play it safe and assume they have side effects.
            return True
        # A Label or ExternalReference can never refer to hardware addresses, only memory
        # allocated by the PLASMA compiler.
        return self.instruction_class in (InstructionClass.ABSOLUTE,) and any(is_hardware_address(address) for address in self.memory())

    @property
    def instruction_class(self):
        return opdict[self.opcode]['class']

    def add_dependencies(self, dependencies):
        # SFTODO TEMP HACK FOR TRANSITION
        if self.instruction_class in (InstructionClass.CONSTANT, InstructionClass.TARGET, InstructionClass.BRANCH, InstructionClass.IMPLIED, InstructionClass.IMMEDIATE1, InstructionClass.IMMEDIATE2, InstructionClass.FRAME, InstructionClass.STRING, InstructionClass.SEL, InstructionClass.CASE_BLOCK):
            pass
        elif self.instruction_class == InstructionClass.ABSOLUTE:
            self.operands[0].add_dependencies(dependencies)
        else:
            assert False # SFTODO SHOULD BE HANDLED BY DERIVED CLASS
            
    def rename_targets(self, alias_dict):
        # SFTODO TEMP HACK FOR TRANSITION
        if self.instruction_class in (InstructionClass.CONSTANT, InstructionClass.TARGET, InstructionClass.IMPLIED, InstructionClass.IMMEDIATE1, InstructionClass.IMMEDIATE2, InstructionClass.ABSOLUTE, InstructionClass.FRAME, InstructionClass.STRING):
            pass
        elif self.instruction_class == InstructionClass.BRANCH:
            self.operands[0] = rename_targets(self.operands[0], alias_dict)
        elif self.instruction_class == InstructionClass.SEL:
            self.operands[0] = rename_targets(self.operands[0], alias_dict)
        elif self.instruction_class == InstructionClass.CASE_BLOCK:
            self.operands[0].rename_targets(alias_dict)
        else:
            assert False # SFTODO SHOULD BE HANDLED BY DERIVED CLASS

    def SFTODORENAMEORDELETE(self, old_label, new_label):
        # SFTODO TEMP HACK
        if self.instruction_class in (InstructionClass.ABSOLUTE,):
            if self.operands[0] is old_label:
                self.operands[0] = new_label
                print('SFTODOX109')

    def add_targets_used(self, targets_used):
        # SFTODO TEMP HACK FOR TRANSITION
        if self.instruction_class in (InstructionClass.CONSTANT, InstructionClass.TARGET, InstructionClass.IMPLIED, InstructionClass.IMMEDIATE1, InstructionClass.IMMEDIATE2, InstructionClass.ABSOLUTE, InstructionClass.FRAME, InstructionClass.STRING):
            pass
        elif self.instruction_class in (InstructionClass.BRANCH, InstructionClass.SEL, InstructionClass.CASE_BLOCK):
            self.operands[0].add_targets_used(targets_used)
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

    def dump(self, outfile, rld):
        InstructionClass.dump(outfile, self, rld)





# TODO: Probably rename Instruction to Op and make corresponding changes in all other class and
# variable names; 'Instruction' is fine in itself, but it's super verbose and it appears one way
# or another all over the code.


# TODO: Crappy way to define this pseudo-opcode
CONSTANT_OPCODE = 0xe1 # SFTODO USE A CONTIGUOUS RANGE FOR ALL PSEUDO-OPCODES
TARGET_OPCODE = 0xff
NOP_OPCODE = 0xf1
CASE_BLOCK_OPCODE = 0xfb



class InstructionClass:
    CONSTANT = 0
    TARGET = 1
    NOP = 2
    BRANCH = 3
    IMPLIED = 4
    IMMEDIATE1 = 5
    IMMEDIATE2 = 6
    ABSOLUTE = 7
    FRAME = 8
    STRING = 9
    SEL = 10
    CASE_BLOCK = 11

    def dump_target(outfile, instruction, rld):
        assert isinstance(instruction.operands[0], Target) # SFTODO TEMP?
        print("%s" % (instruction.operands[0]), file=outfile)


    def dump_case_block(outfile, instruction, rld):
        table = instruction.operands[0].table
        print("\t!BYTE\t$%02X\t\t\t; CASEBLOCK" % (len(table),), file=outfile)
        for value, target in table:
            print("\t!WORD\t$%04X" % (value,), file=outfile)
            print("\t!WORD\t%s-*" % (target,), file=outfile)


    def disassemble_branch(disassembly_info, i):
        opcode = disassembly_info.labelled_blob[i]
        # SFTODO: Validate opcode?? Arguably redundant given how this is called
        target, i = Target.disassemble(disassembly_info, i+1)
        return Instruction(opcode, [target]), i

    def dump_branch(outfile, instruction, rld):
        opcode = instruction.opcode
        operands = instruction.operands
        print("\t!BYTE\t$%02X\t\t\t; %s\t%s" % (opcode, opdict[opcode]['opcode'], operands[0]), file=outfile)
        print("\t!WORD\t%s-*" % (operands[0],), file=outfile)


    def disassemble_sel(di, i):
        i += 1
        di.case_block_offsets.add(i + di.labelled_blob.read_u16(i))
        target, i = Target.disassemble(di, i)
        return Instruction('SEL', [target]), i



    def disassemble_implied_instruction(disassembly_info, i):
        opcode = disassembly_info.labelled_blob[i]
        # SFTODO: Validate opcode?? Arguably redundant given how this is called
        return Instruction(opcode, []), i+1

    def dump_implied_instruction(outfile, instruction, rld):
        print("\t!BYTE\t$%02X\t\t\t; %s" % (instruction.opcode, opdict[instruction.opcode]['opcode']), file=outfile)



    @staticmethod
    def disassemble_immediate_instruction(disassembly_info, i, operand_count):
        opcode = disassembly_info.labelled_blob[i]
        # SFTODO: Validate opcode?? Arguably redundant given how this is called
        i += 1
        operands = []
        for j in range(operand_count):
            operands.append(Byte(disassembly_info.labelled_blob[i]))
            i += 1
        return Instruction(opcode, operands), i

    def disassemble_immediate_instruction1(disassembly_info, i):
        return InstructionClass.disassemble_immediate_instruction(disassembly_info, i, 1)

    def disassemble_immediate_instruction2(disassembly_info, i):
        return InstructionClass.disassemble_immediate_instruction(disassembly_info, i, 2)

    def dump_immediate_instruction(outfile, instruction, rld): # SFTODO: RENAME SELF
        if len(instruction.operands) == 1:
            print("\t!BYTE\t$%02X,$%02X\t\t\t; %s\t%s" % (instruction.opcode, instruction.operands[0].value, opdict[instruction.opcode]['opcode'], instruction.operands[0].value), file=outfile)
        elif len(instruction.operands) == 2:
            print("\t!BYTE\t$%02X,$%02X,$%02X\t\t; %s\t%s,%s" % (instruction.opcode, instruction.operands[0].value, instruction.operands[1].value, opdict[instruction.opcode]['opcode'], instruction.operands[0].value, instruction.operands[1].value), file=outfile)
        else:
            assert False



    def disassemble_absolute_instruction(disassembly_info, i):
        opcode = disassembly_info.labelled_blob[i]
        # SFTODO: Validate opcode?? Arguably redundant given how this is called
        i += 1
        address, i = AbsoluteAddress.disassemble(disassembly_info, i)
        return Instruction(opcode, [address]), i



    def disassemble_frame_instruction(disassembly_info, i):
        opcode = disassembly_info.labelled_blob[i]
        # TODO: I think FrameOffset probably adds very little and we should just use a raw int here, but let's not try to get rid of it just yet - OK, I am now thinking it does have value, since memory() returns a set of addresses and these can be mixed together from various instructions, so having a 'type' is handy
        frame_offset = FrameOffset(disassembly_info.labelled_blob[i+1])
        return Instruction(opcode, [frame_offset]), i+2

    def dump_frame_instruction(outfile, instruction, rld):
        print("\t!BYTE\t$%02X,$%02X\t\t\t; %s\t[%s]" % (instruction.opcode, instruction.operands[0].value, opdict[instruction.opcode]['opcode'], instruction.operands[0].value), file=outfile)



    def disassemble_string_instruction(disassembly_info, i):
        s, i = String.disassemble(disassembly_info, i+1)
        return Instruction(0x2e, [s]), i

    def dump_string_instruction(outfile, instruction, rld):
        s = instruction.operands[0].value
        print("\t!BYTE\t$2E\t\t\t; CS\t%r" % (s,), file=outfile) # SFTODO: REPR NOT PERFECT BUT WILL DO - IT CAN USE SINGLE QUOTES TO WRAP THE STRING WHICH ISN'T IDEAL
        print("\t!BYTE\t$%02X" % (len(s),), file=outfile)
        while s:
            t = s[0:8]
            s = s[8:]
            print("\t!BYTE\t" + ",".join("$%02X" % ord(c) for c in t), file=outfile)

    def dump_absolute_instruction(outfile, instruction, rld):
        instruction.operands[0].dump(outfile, instruction.opcode, rld)

    def disassemble_constant(disassembly_info, i):
        opcode = disassembly_info.labelled_blob[i]
        if opcode <= 0x1e: # CN opcode
            return Instruction(CONSTANT_OPCODE, [opcode/2]), i+1
        elif opcode == 0x20: # MINUS ONE opcode
            return Instruction(CONSTANT_OPCODE, [-1]), i+1
        elif opcode == 0x2a: # CB opcode
            return Instruction(CONSTANT_OPCODE, [disassembly_info.labelled_blob[i+1]]), i+2
        elif opcode == 0x2c: # CW opcode
            # SFTODO: Should I sign-extend here? It's not *wrong* but it may cause us to fail
            # to recognise that two constants are identical and it just seems a bit
            # inconsistent. Or, alternatively, CFFB *should* sign-extend for consistency.
            return Instruction(CONSTANT_OPCODE, [sign_extend(disassembly_info.labelled_blob.read_u16(i+1))]), i+3
        elif opcode == 0x5e: # CFFB opcode
            return Instruction(CONSTANT_OPCODE, [0xff00 | disassembly_info.labelled_blob[i+1]]), i+2
        else:
            print('SFTODO %02x' % opcode)
            assert False

    def dump_constant(outfile, instruction, rld):
        value = instruction.operands[0]
        if value >= 0 and value < 16:
            print("\t!BYTE\t$%02X\t\t\t; CN\t%d" % (value << 1, value), file=outfile)
        elif value >= 0 and value < 256:
            print("\t!BYTE\t$2A,$%02X\t\t\t; CB\t%d" % (value, value), file=outfile)
        elif value == -1:
            print("\t!BYTE\t$20\t\t\t; MINUS ONE", file=outfile)
        elif value & 0xff00 == 0xff00:
            print("\t!BYTE\t$5E,$%02X\t\t\t; CFFB\t%d" % (value & 0xff, value), file=outfile)
        else:
            print("\t!BYTE\t$2C,$%02X,$%02X\t\t; CW\t%d" % (value & 0xff, (value & 0xff00) >> 8, value), file=outfile)

    # SFTODO: Permanent comment if this lives and if I have the idea right - we are kind of implementing our own vtable here, which sucks a bit, but by doing this we can allow an Instruction object to be updated in-place to changes it opcode, which isn't possible if we use actual Python inheritance as the object's type can be changed. I am hoping that this will allow optimisations to be written more naturally, since it will be possible to change an instruction (which will work via standard for instruction in list stuff) rather than having to replace it (which requires forcing the use of indexes into the list so we can do ops[i] = NewInstruction())
    # SFTODO: MAYBE MAKE THIS DICT AND THE FUNCTIONS IT REFERENCES ALL MEMBERS OF
    # InstructionClass - THAT WAY WE CAN GET RID OF THE INSTRUCTIONCLASS PREFIX AND IT WILL
    # PROVIDE SOME GROUPING OF THEM - THEN PERHAPS WE CAN HAVE @classmethod
    # Instruction.disassemble() WHICH WILL USE InstructionClass OR SOMETHING
    instruction_class_fns = {
            NOP: {'operands': 0},
            TARGET: {'dump': dump_target, 'operands': 1, 'operand_type': Target},
            CONSTANT: {'disassemble': disassemble_constant, 'dump': dump_constant, 'operands': 1, 'operand_type': int},
            BRANCH: {'disassemble': disassemble_branch, 'dump': dump_branch, 'operands': 1, 'operand_type': Target},
            IMPLIED: {'disassemble': disassemble_implied_instruction, 'dump': dump_implied_instruction, 'operands': 0},
            IMMEDIATE1: {'disassemble': disassemble_immediate_instruction1, 'dump': dump_immediate_instruction, 'operands': 1, 'operand_type': Byte},
            IMMEDIATE2: {'disassemble': disassemble_immediate_instruction2, 'dump': dump_immediate_instruction, 'operands': 2, 'operand_type': Byte},
            ABSOLUTE: {'disassemble': disassemble_absolute_instruction, 'dump': dump_absolute_instruction, 'operands': 1, 'operand_type': AbsoluteAddress},
            FRAME: {'disassemble': disassemble_frame_instruction, 'dump': dump_frame_instruction, 'operands': 1, 'operand_type': FrameOffset},
            STRING: {'disassemble': disassemble_string_instruction, 'dump': dump_string_instruction, 'operands': 1, 'operand_type': String},
            SEL: {'disassemble': disassemble_sel, 'dump': dump_branch, 'operands': 1, 'operand_type': Target},
            CASE_BLOCK: {'dump': dump_case_block, 'operands': 1, 'operand_type': CaseBlock},
    }

    @staticmethod
    def disassemble(instruction_class, di, i):
        dis = InstructionClass.instruction_class_fns[instruction_class]['disassemble']
        return dis(di, i)

    @staticmethod
    def dump(outfile, instruction, rld):
        InstructionClass.instruction_class_fns[instruction.instruction_class]['dump'](outfile, instruction, rld)

    @staticmethod
    def validate_instruction(instruction): # SFTODO: RENAME TO validate_operands?
        ic = InstructionClass.instruction_class_fns[instruction.instruction_class]
        assert len(instruction.operands) == ic['operands']
        assert all(isinstance(operand, ic['operand_type']) for operand in instruction.operands)




# TODO: Check this table is complete and correct
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
    0x30: {'opcode': 'DROP', 'class': InstructionClass.IMPLIED},
    0x32: {'opcode': 'DROP2', 'class': InstructionClass.IMPLIED},
    0x34: {'opcode': 'DUP', 'class': InstructionClass.IMPLIED},
    0x38: {'opcode': 'ADDI', 'class': InstructionClass.IMMEDIATE1},
    0x3a: {'opcode': 'SUBI', 'class': InstructionClass.IMMEDIATE1},
    0x3c: {'opcode': 'ANDI', 'class': InstructionClass.IMMEDIATE1},
    0x3e: {'opcode': 'ORI', 'class': InstructionClass.IMMEDIATE1},
    0x40: {'opcode': 'ISEQ', 'class': InstructionClass.IMPLIED},
    0x42: {'opcode': 'ISNE', 'class': InstructionClass.IMPLIED},
    0x44: {'opcode': 'ISGT', 'class': InstructionClass.IMPLIED},
    0x46: {'opcode': 'ISLT', 'class': InstructionClass.IMPLIED},
    0x48: {'opcode': 'ISGE', 'class': InstructionClass.IMPLIED},
    0x4a: {'opcode': 'ISLE', 'class': InstructionClass.IMPLIED},
    0x4c: {'opcode': 'BRFLS', 'class': InstructionClass.BRANCH},
    0x4e: {'opcode': 'BRTRU', 'class': InstructionClass.BRANCH},
    0x50: {'opcode': 'BRNCH', 'class': InstructionClass.BRANCH, 'terminator': True},
    0x52: {'opcode': 'SEL', 'class': InstructionClass.SEL},
    0x54: {'opcode': 'CALL', 'class': InstructionClass.ABSOLUTE}, # SFTODO: MemoryInstruction isn't necessarily best class here, but let's try it for now
    0x56: {'opcode': 'ICAL', 'class': InstructionClass.IMPLIED},
    0x58: {'opcode': 'ENTER', 'class': InstructionClass.IMMEDIATE2},
    0x5c: {'opcode': 'RET', 'terminator': True, 'class': InstructionClass.IMPLIED},
    0x5a: {'opcode': 'LEAVE', 'terminator': True, 'class': InstructionClass.IMMEDIATE1},
    0x5e: {'opcode': 'CFFB', 'class': InstructionClass.CONSTANT},
    0x60: {'opcode': 'LB', 'is_load': True, 'class': InstructionClass.IMPLIED},
    0x62: {'opcode': 'LW', 'is_load': True, 'class': InstructionClass.IMPLIED},
    0x64: {'opcode': 'LLB', 'is_load': True, 'data_size': 1, 'class': InstructionClass.FRAME},
    0x66: {'opcode': 'LLW', 'is_load': True, 'data_size': 2, 'class': InstructionClass.FRAME},
    0x68: {'opcode': 'LAB', 'is_load': True, 'data_size': 1, 'class': InstructionClass.ABSOLUTE},
    0x6a: {'opcode': 'LAW', 'is_load': True, 'data_size': 2, 'class': InstructionClass.ABSOLUTE},
    0x6c: {'opcode': 'DLB', 'is_dup_store': True, 'data_size': 1, 'class': InstructionClass.FRAME},
    0x6e: {'opcode': 'DLW', 'is_dup_store': True, 'data_size': 2, 'class': InstructionClass.FRAME},
    0x70: {'opcode': 'SB', 'is_store': True, 'class': InstructionClass.IMPLIED},
    0x72: {'opcode': 'SW', 'is_store': True, 'class': InstructionClass.IMPLIED},
    0x74: {'opcode': 'SLB', 'is_store': True, 'data_size': 1, 'class': InstructionClass.FRAME},
    0x76: {'opcode': 'SLW', 'is_store': True, 'data_size': 2, 'class': InstructionClass.FRAME},
    0x78: {'opcode': 'SAB', 'is_store': True, 'data_size': 1, 'class': InstructionClass.ABSOLUTE},
    0x7a: {'opcode': 'SAW', 'is_store': True, 'data_size': 2, 'class': InstructionClass.ABSOLUTE},
    0x7c: {'opcode': 'DAB', 'is_dup_store': True, 'data_size': 1, 'class': InstructionClass.ABSOLUTE},
    0x7e: {'opcode': 'DAW', 'is_dup_store': True, 'data_size': 2, 'class': InstructionClass.ABSOLUTE},
    0x80: {'opcode': 'LNOT', 'class': InstructionClass.IMPLIED},
    0x82: {'opcode': 'ADD', 'class': InstructionClass.IMPLIED},
    0x84: {'opcode': 'SUB', 'class': InstructionClass.IMPLIED},
    0x86: {'opcode': 'MUL', 'class': InstructionClass.IMPLIED},
    0x88: {'opcode': 'DIV', 'class': InstructionClass.IMPLIED},
    0x8a: {'opcode': 'MOD', 'class': InstructionClass.IMPLIED},
    0x8c: {'opcode': 'INCR', 'class': InstructionClass.IMPLIED},
    0x8e: {'opcode': 'DECR', 'class': InstructionClass.IMPLIED},
    0x90: {'opcode': 'NEG', 'class': InstructionClass.IMPLIED},
    0x92: {'opcode': 'COMP', 'class': InstructionClass.IMPLIED},
    0x94: {'opcode': 'BAND', 'class': InstructionClass.IMPLIED},
    0x96: {'opcode': 'IOR', 'class': InstructionClass.IMPLIED},
    0x98: {'opcode': 'XOR', 'class': InstructionClass.IMPLIED},
    0x9a: {'opcode': 'SHL', 'class': InstructionClass.IMPLIED},
    0x9c: {'opcode': 'SHR', 'class': InstructionClass.IMPLIED},
    0x9e: {'opcode': 'IDXW', 'class': InstructionClass.IMPLIED},
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
    TARGET_OPCODE: {'pseudo': True, 'class': InstructionClass.TARGET},
    NOP_OPCODE: {'pseudo': True, 'class': InstructionClass.NOP},
    CASE_BLOCK_OPCODE: {'pseudo': True, 'class': InstructionClass.CASE_BLOCK},
}

opcode = {v['opcode']: k for (k, v) in opdict.items() if not v.get('pseudo', False)}


class DisassemblyInfo(object):
    """Collection of temporary information needed while disassembling a bytecode
       function; can be discarded once disassembly is complete."""
    def __init__(self, bytecode_function, labelled_blob):
        self.bytecode_function = bytecode_function
        self.labelled_blob = labelled_blob
        self.target = collections.defaultdict(list)
        self.case_block_offsets = set()

class BytecodeFunction(object):
    def __init__(self, labelled_blob):
        assert isinstance(labelled_blob, LabelledBlob)
        self.labels = labelled_blob.labels.get(0, [])
        for label in self.labels:
            label.set_owner(self)
        if len(self.labels) > 0:
            print('SFTODOXX12', self.labels[0].name)
            assert self.labels[0].name[0:2] == '_I'
        ops = [] # SFTODO Should perhaps call 'instructions'
        di = DisassemblyInfo(self, labelled_blob)

        i = 0
        op_offset = []
        while i < len(labelled_blob):
            # There should be no labels within a bytecode function. We will later
            # create branch targets based on the branch instructions within
            # the function, but those are different.
            assert i == 0 or i not in labelled_blob.labels

            op_offset.append(i)

            if i not in di.case_block_offsets:
                opcode = labelled_blob[i]
                #print('SFTODOQQ %X' % opcode)
                opdef = opdict[opcode]
                assert not opdef.get('pseudo')
                op, i = InstructionClass.disassemble(opdef['class'], di, i)
            else:
                operand, i = CaseBlock.disassemble(di, i)
                op = Instruction(CASE_BLOCK_OPCODE, [operand])
            ops.append(op)

        self.ops = []
        for i, op in enumerate(ops):
            for t in di.target.get(op_offset[i], []):
                self.ops.append(Instruction(TARGET_OPCODE, [t]))
            self.ops.append(op)

    def is_init(self):
        return any(x.name == '_INIT' for x in self.labels)

    def add_dependencies(self, dependencies):
        if self in dependencies:
            return
        dependencies.add(self)
        for instruction in self.ops:
            instruction.add_dependencies(dependencies)

    # TODO: Bad name (I think because it's more "things we reference some way or other", not "functions we call" - they may be global variables)
    # TODO: Delete if not used
    def callees(self):
        result = set()
        for instruction in self.ops:
            if instruction.instruction_class == InstructionClass.ABSOLUTE:
                operand = instruction.operands[0]
                if isinstance(operand, Label):
                    result.add(operand)
        return result

    def dump(self, outfile, rld):
        if not self.is_init():
            label = rld.get_bytecode_function_label()
            print(label.name, file=outfile)
        for label in self.labels:
            print(label.name, file=outfile)
        for instruction in self.ops:
            instruction.dump(outfile, rld)

# SFTODO: Experimental - this can't be a member of Target because now Target is used
# for both target instructions and branch instruction operands, the (unavoidable,
# given how I want to write the code) copying of operands between instructions means
# that target instructions and branches end up sharing a single Target object. We therefore
# must not mutate an Target object as it affects everything holding a reference to it;
# we must replace the Target object we're interested in with another one with the
# relevant change. This has been hacked in to test this change, and it does seem to
# work, but it's pretty messy the way some objects *do* have rename_targets() as
# a member but we have to remember to use this in some places.
def rename_targets(target, alias):
    assert isinstance(target, Target)
    assert isinstance(alias, dict)
    assert all(isinstance(k, Target) and isinstance(v, Target) for k,v in alias.items())
    return Target(alias.get(target, target)._value)


def is_hardware_address(address):
    # SFTODO: Again the 'address as generic term' and 'FixedAddress as an absolute address' awkwardness...
    # TODO: 0xc000 is a crude compromise for Acorn and Apple; might be nice to
    # support a better compromise and perhaps offer a --platform command line
    # switch to trigger a tighter definition where platform is known.
    # TODO: It might be good to allow a command line option to pretend *all* addresses are
    # hardware addresses and/or to allow specific addresses to be flagged as hardware
    # addresses. This might be important if PLASMA code were trying to interoperate with a
    # machine code interrupt handler using a normal memory address as a mutex or similar.
    # If I make this change, this function should perhaps rename to is_volatile_address()
    # or is_sensitive_address() or something like that.
    return isinstance(address, FixedAddress) and address.value >= 0xc000


# TODO: Seems wrong to have these random free functions

def acme_dump_fixup(outfile, rld, reference, comment=True):
    fixup_label = Label('_F')
    rld.add_fixup(reference, fixup_label)
    print('%s\t%s' % (fixup_label.name, reference.acme_reference(comment)), file=outfile)



# SFTODO: Move this into bytecode.py? Though maybe need to rename the file if it starts to
# represent modules (which aren't pure bytecode)
class Module(object):
    def __init__(self, sysflags, import_names, esd):
        self.sysflags = sysflags # SFTODO!?
        self.import_names = import_names # SFTODO!?
        self.data_asm_blob = None # SFTODO!?
        self.bytecode_functions = []
        self.esd = esd # SFTODO!?

    @classmethod
    def load(cls, f):
        seg_size = read_u16(f)
        magic = read_u16(f)
        if magic != 0x6502:
            die("Input file is not a valid PLASMA module")
        sysflags = read_u16(f)
        subseg_abs = read_u16(f)
        defcnt = read_u16(f)
        init_abs = read_u16(f)

        import_names = []
        while True:
            import_name = read_dci(f)
            if import_name == '\0':
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
            if esd_name == '\0':
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
                print('SFTODOXX19s', label.name, blob_index) 
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

        module = Module(sysflags, import_names, new_esd)
        module.data_asm_blob = blob[0:subseg_abs - org - blob_offset]

        offsets = bytecode_function_offsets + [init_offset, len(blob)]
        for start, end in zip(offsets, offsets[1:]):
            bytecode_function_blob = blob[start:end]
            module.bytecode_functions.append(BytecodeFunction(bytecode_function_blob))

        del blob
        del rld
        del esd
        del defcnt

        return module


    # TODO: New experimental stuff delete if not used
    # TODO: Poor name just as the callees() function it calls
    def callees(self):
        result = set()
        for bytecode_function in self.bytecode_functions:
            result.update(bytecode_function.callees())
        return result

    def bytecode_function_labels(self):
        result = set()
        for bytecode_function in self.bytecode_functions:
            assert len(bytecode_function.labels) <= 1
            # Bytecode functions which aren't exported and never called don't have any
            # labels; the optimiser will get rid of these, but it may not be enabled.
            if len(bytecode_function.labels) > 0:
                result.add(bytecode_function.labels[0])
        return result

    def dump(self, outfile):
        print("\t!WORD\t_SEGEND-_SEGBEGIN\t; LENGTH OF HEADER + CODE/DATA + BYTECODE SEGMENT", file=outfile)
        print("_SEGBEGIN", file=outfile)
        print("\t!WORD\t$6502\t\t\t; MAGIC #", file=outfile)
        print("\t!WORD\t%d\t\t\t; SYSTEM FLAGS" % (self.sysflags,), file=outfile)
        print("\t!WORD\t_SUBSEG\t\t\t; BYTECODE SUB-SEGMENT", file=outfile)
        print("\t!WORD\t_DEFCNT\t\t\t; BYTECODE DEF COUNT", file=outfile)
        if self.bytecode_functions[-1].is_init():
            print("\t!WORD\t_INIT\t\t\t; MODULE INITIALIZATION ROUTINE", file=outfile)
        else:
            print("\t!WORD\t0\t\t\t; MODULE INITIALIZATION ROUTINE", file=outfile)

        for import_name in self.import_names:
            print("\t; DCI STRING: %s" % (import_name,), file=outfile)
            print("\t!BYTE\t%s" % dci_bytes(import_name), file=outfile)
        print("\t!BYTE\t$00\t\t\t; END OF MODULE DEPENDENCIES", file=outfile)

        rld = RLD()

        # TODO: Either here or as an earlier "optimisation", we could prune things from
        # self.esd which are not actually referenced (or avoid outputting them; maybe
        # dump() shouldn't modify self.esd - but nothing wrong with an optimise step
        # modifying it earlier, if that's easier). This wouldn't affect the memory
        # used at run time (except for temporarily during module loading) but would
        # fractionally speed up loading due to less searching and would shrink the size on
        # disc.

        if self.data_asm_blob is not None:
            self.data_asm_blob.dump(outfile, rld)

        print("_SUBSEG", file=outfile)
        for bytecode_function in self.bytecode_functions:
            bytecode_function.dump(outfile, rld)
        defcnt = len(self.bytecode_functions)
        print("_DEFCNT = %d" % (defcnt,), file=outfile)
        print("_SEGEND", file=outfile)

        rld.dump(outfile, self.esd)

        self.esd.dump(outfile)

    # This is very crude; it just moves the data/asm blob into a second module, then
    # repeatedly moves functions in this module which only reference things in the second
    # module into the second module themselves until it runs out of things to move. It
    # makes no attempt to intelligently move blocks of functions, or to hit any size
    # targets on the two modules. (I did experiment with using graph partitioning
    # algorithms in scipy to help with this, but I couldn't see how to model the
    # constraint that nothing in the second module can call into this module.) The main
    # use for this is to allow the self-hosted compiler to be split so it can run under
    # PLAS128 on Acorn machines; PLAS128 has a limit of (just under) 16K for any single
    # module, and it just so happens that this crude algorithm produces two suitably sized
    # modules when run on the current version of the self-hosted compiler.
    def split(self, second_module_name):
        """Return a new module which has had some of the contents of the current module
           moved into it; the current module has the new module added as a dependency."""

        second_module = Module(self.sysflags, self.import_names, ESD())
        self.import_names = [second_module_name]
        second_module.data_asm_blob = self.data_asm_blob
        self.data_asm_blob = None

        caller_module = self 
        callee_module = second_module
        data_asm_blob_labels = set()
        for SFTODO in callee_module.data_asm_blob.labels.values():
            for SFTODO2 in SFTODO:
                data_asm_blob_labels.add(SFTODO2)
        while True:
            print('SFTODOFF4')
            changed = False
            for i, bytecode_function in enumerate(caller_module.bytecode_functions):
                if i == 0:
                    print('SFTODOQQX', [x.name for x in bytecode_function.callees()])
                if bytecode_function.callees().issubset(callee_module.bytecode_function_labels().union(data_asm_blob_labels)):
                    print('SFTODOQ43', i)
                    callee_module.bytecode_functions.append(caller_module.bytecode_functions[i])
                    caller_module.bytecode_functions[i] = None
                    changed = True
            caller_module.bytecode_functions = [x for x in caller_module.bytecode_functions if x is not None]
            if not changed:
                break


        # TODO: Move this function if it lives
        def compact_int(i):
            """Return a short string representation encoding an integer"""
            assert i >= 0
            # TODO: These larger character sets don't work - the modules fail to load due to missing
            # symbols - but I can't see why.
            #character_set = [chr(x) for x in range(33, 127)]
            #character_set = [chr(x) for x in range(33, 127) if x not in range(ord('a'), ord('z')+1) ]
            character_set = [chr(x) for x in range(33, 97)]
            if i == 0:
                return character_set[0]
            base = len(character_set)
            result = ''
            while i > 0:
                result += character_set[i % base]
                i = i // base
            return result




        # TODO: Move this into a function?
        # Patch up the two modules so we have correct external references following the function moves.
        # SFTODO: callees() should probably be renamed and it should probably return all labels referenced
        while True:
            callees_in_caller_module = callee_module.callees().intersection(caller_module.bytecode_function_labels())
            print('SFTODOX1033', len(callees_in_caller_module))
            if len(callees_in_caller_module) > 0:
                for i, bytecode_function in enumerate(caller_module.bytecode_functions):
                    if bytecode_function.labels[0] in callees_in_caller_module:
                        callee_module.bytecode_functions.append(caller_module.bytecode_functions[i])
                        caller_module.bytecode_functions[i] = None
                        callees_in_caller_module.remove(bytecode_function.labels[0])
                assert len(callees_in_caller_module) == 0
                caller_module.bytecode_functions = [x for x in caller_module.bytecode_functions if x is not None]
            else:
                break
        callee_module_new_exports = caller_module.callees().intersection(callee_module.bytecode_function_labels())
        callee_module_new_exports.update(data_asm_blob_labels)
        print('SFTODOQE3', len(callee_module_new_exports))
        SFTODOHACKCOUNT = 0
        for export in callee_module_new_exports:
            # SFTODO: Inefficient
            external_name = None
            for esd_external_name, reference in caller_module.esd.entry_dict.items():
                if export == reference:
                    external_name = esd_external_name
                    del caller_module.esd.entry_dict[esd_external_name]
                    break
            if external_name is None:
                # TODO: Using a shorter and better external name would reduce the on-disc size of the modules which would be helpful in terms of loading them on machines with less main RAM...
                # TODO: The '!' character used here should be overridable on the command line just in case.
                external_name = '!%s' % compact_int(SFTODOHACKCOUNT)
                SFTODOHACKCOUNT += 1
            external_reference = ExternalReference(external_name, 0)
            for bytecode_function in caller_module.bytecode_functions:
                # SFTODO: Make the following loop a member function of BytecodeFunction?
                for instruction in bytecode_function.ops:
                    instruction.SFTODORENAMEORDELETE(export, external_reference)
            callee_module.esd.add_entry(external_name, export)
        # SFTODO: Any external references in caller_module which have been moved to callee_module need to be exported with the correct name in caller_module - right now this is all an experimental mess and I can't fucking concentrate for five minutes without being interrupted

        return second_module



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
    s += chr(c)
    return s

def dci_bytes(s):
    result = ''
    for c in s[0:-1]:
        result += '$%02X,' % (ord(c) | 0x80)
    result += '$%02X' % ord(s[-1])
    return result

# TODO: All the 'dump' type functions should probably have a target-type in the name (e.g. acme_dump() or later I will have a binary_dump() which outputs a module directly)

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

    def SFTODORENAMEORDELETE(self, old_reference, new_reference):
        assert isinstance(old_reference, Label)
        assert isinstance(new_reference, ExternalReference)
        for i, (reference, fixup_label) in self.fixups:
            if reference == old_reference:
                self.fixups[i] = (new_reference, fixup_label)
                print('SFTODOQ4554')

    def dump(self, outfile, esd):
        print(";\n; RE-LOCATEABLE DICTIONARY\n;", file=outfile)

        # The first part of the RLD must be what cmd.pla calls the "DeFinition Dictionary".
        for bytecode_function_label in self.bytecode_function_labels:
            print(bytecode_function_label.acme_def(bytecode_function_label), file=outfile)

        # Although the PLASMA VM doesn't strictly care what order the internal and
        # external fixups appear in in the rest of the RLD, cmd.pla's reloc() function
        # special-cases internal fixups to non-bytecode addresses and handles them
        # internally without returning to the caller. I haven't actually tried to measure
        # this, but this means that if we group all the internal fixups to non-bytecode
        # addresses together we should get an improvement (perhaps a negligible one) in the
        # time taken to load the module.
        pending = []
        for reference, fixup_label in self.fixups:
            rld_str = reference.acme_rld(fixup_label, esd)
            if isinstance(reference, Label) and isinstance(reference.owner, LabelledBlob):
                print(rld_str, file=outfile)
            else:
                pending.append(rld_str)
        print("\n".join(pending), file=outfile)

        print("\t!BYTE\t$00\t\t\t; END OF RLD", file=outfile)


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

    def dump(self, outfile):
        # Although the PLASMA VM doesn't care:
        # - We output all the EXTERNAL SYMBOL entries first followed by the ENTRY SYMBOL
        #   entries, to match the output generated by the PLASMA compiler.
        # - We output the EXTERNAL SYMBOL entries in order of their ESD index, just for
        #   neatness.

        print(";\n; EXTERNAL/ENTRY SYMBOL DICTIONARY\n;", file=outfile)

        external_symbol_by_esd_index = [None] * len(self.external_dict)
        for external_name, esd_index in self.external_dict.items():
            external_symbol_by_esd_index[esd_index] = external_name
        for esd_index, external_name in enumerate(external_symbol_by_esd_index):
            print("\t; DCI STRING: %s" % external_name, file=outfile)
            print("\t!BYTE\t%s" % dci_bytes(external_name), file=outfile)
            print("\t!BYTE\t$10\t\t\t; EXTERNAL SYMBOL FLAG", file=outfile)
            print("\t!WORD\t%d\t\t\t; ESD INDEX" % (esd_index,), file=outfile)

        for external_name, reference in self.entry_dict.items():
            assert isinstance(reference, Label)
            print("\t; DCI STRING: %s" % external_name, file=outfile)
            print("\t!BYTE\t%s" % dci_bytes(external_name), file=outfile)
            print("\t!BYTE\t$08\t\t\t; ENTRY SYMBOL FLAG", file=outfile)
            print('\t%s' % (reference.acme_reference(),), file=outfile)

        print("\t!BYTE\t$00\t\t\t; END OF ESD", file=outfile)






