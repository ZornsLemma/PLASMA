from __future__ import print_function

import collections

from operands import *
from utils import *

# Pseudo-opcodes; we give these non-8-bit values as extra insurance against them making
# their way into the output without being noticed.
CONSTANT_OPCODE = -1000
TARGET_OPCODE = -1001
NOP_OPCODE = -1002
CASE_BLOCK_OPCODE = -1003



# I originally used inheritance to model the different types of instruction, with
# Instruction as a base class, but this was inconvenient as it was not possible to update
# an Instruction in-place freely (an object can't change its type) and this is
# useful when implementing optimisations; if you can modify an object in place you can use
# Python's for loop to modify sequences, whereas replacing an object requires
# knowing its sequence index. Instead each Instruction has an InstructionClass (looked up
# based on its opcode) which provides a place to describe the differences common to each
# instruction class without using inheritance.



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
        print("%s" % (instruction.operands[0]), file=outfile)


    def dump_case_block(outfile, instruction, rld):
        table = instruction.operands[0].table
        print("\t!BYTE\t$%02X\t\t\t; CASEBLOCK" % (len(table),), file=outfile)
        for value, target in table:
            print("\t!WORD\t$%04X" % (value,), file=outfile)
            print("\t!WORD\t%s-*" % (target,), file=outfile)


    def disassemble_branch(disassembly_info, i):
        opcode = disassembly_info.labelled_blob[i]
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
        return Instruction(opcode, []), i+1

    def dump_implied_instruction(outfile, instruction, rld):
        print("\t!BYTE\t$%02X\t\t\t; %s" % (instruction.opcode, opdict[instruction.opcode]['opcode']), file=outfile)



    @staticmethod
    def disassemble_immediate_instruction(disassembly_info, i, operand_count):
        opcode = disassembly_info.labelled_blob[i]
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

    def dump_immediate_instruction(outfile, instruction, rld):
        if len(instruction.operands) == 1:
            print("\t!BYTE\t$%02X,$%02X\t\t\t; %s\t%s" % (instruction.opcode, instruction.operands[0].value, opdict[instruction.opcode]['opcode'], instruction.operands[0].value), file=outfile)
        elif len(instruction.operands) == 2:
            print("\t!BYTE\t$%02X,$%02X,$%02X\t\t; %s\t%s,%s" % (instruction.opcode, instruction.operands[0].value, instruction.operands[1].value, opdict[instruction.opcode]['opcode'], instruction.operands[0].value, instruction.operands[1].value), file=outfile)
        else:
            assert False

    # SFTODO: All these functions need reordering logically and perhaps some consistency about whether they have _instruction at the end of their name


    def disassemble_absolute_instruction(disassembly_info, i):
        opcode = disassembly_info.labelled_blob[i]
        i += 1
        address, i = AbsoluteAddress.disassemble(disassembly_info, i)
        return Instruction(opcode, [address]), i



    def disassemble_frame_instruction(disassembly_info, i):
        opcode = disassembly_info.labelled_blob[i]
        frame_offset = FrameOffset(disassembly_info.labelled_blob[i+1])
        return Instruction(opcode, [frame_offset]), i+2

    def dump_frame_instruction(outfile, instruction, rld):
        print("\t!BYTE\t$%02X,$%02X\t\t\t; %s\t[%s]" % (instruction.opcode, instruction.operands[0].value, opdict[instruction.opcode]['opcode'], instruction.operands[0].value), file=outfile)



    def disassemble_string_instruction(disassembly_info, i):
        s, i = String.disassemble(disassembly_info, i+1)
        return Instruction(0x2e, [s]), i

    def dump_string_instruction(outfile, instruction, rld):
        s = instruction.operands[0].value
        t = ''
        for c in s:
            if c == '"':
                t += r'\"'
            elif c == "'":
                t += "'"
            else:
                t += repr(c)[1:-1]

        print('\t!BYTE\t$2E\t\t\t; CS\t"%s"' % (t,), file=outfile)
        print("\t!BYTE\t$%02X" % (len(s),), file=outfile)
        while s:
            t = s[0:8]
            s = s[8:]
            print("\t!BYTE\t" + ",".join("$%02X" % ord(c) for c in t), file=outfile)

    def dump_absolute_instruction(outfile, instruction, rld):
        instruction.operands[0].dump(outfile, instruction.opcode, rld, opdict)

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
            return Instruction(CONSTANT_OPCODE, [sign_extend(0xff00 | disassembly_info.labelled_blob[i+1])]), i+2
        else:
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

    instruction_class_fns = {
            NOP: {'operand_types': []},
            TARGET: {'dump': dump_target, 'operand_types': [Target]},
            CONSTANT: {'disassemble': disassemble_constant, 'dump': dump_constant, 'operand_types': [int]},
            BRANCH: {'disassemble': disassemble_branch, 'dump': dump_branch, 'operand_types': [Target]},
            IMPLIED: {'disassemble': disassemble_implied_instruction, 'dump': dump_implied_instruction, 'operand_types': []},
            IMMEDIATE1: {'disassemble': disassemble_immediate_instruction1, 'dump': dump_immediate_instruction, 'operand_types': [Byte]},
            IMMEDIATE2: {'disassemble': disassemble_immediate_instruction2, 'dump': dump_immediate_instruction, 'operand_types': [Byte, Byte]},
            ABSOLUTE: {'disassemble': disassemble_absolute_instruction, 'dump': dump_absolute_instruction, 'operand_types': [AbsoluteAddress]},
            FRAME: {'disassemble': disassemble_frame_instruction, 'dump': dump_frame_instruction, 'operand_types': [FrameOffset]},
            STRING: {'disassemble': disassemble_string_instruction, 'dump': dump_string_instruction, 'operand_types': [String]},
            SEL: {'disassemble': disassemble_sel, 'dump': dump_branch, 'operand_types': [Target]},
            CASE_BLOCK: {'dump': dump_case_block, 'operand_types': [CaseBlock]},
    }

    @staticmethod
    def disassemble(instruction_class, di, i):
        dis = InstructionClass.instruction_class_fns[instruction_class]['disassemble']
        return dis(di, i)

    @staticmethod
    def dump(outfile, instruction, rld):
        InstructionClass.instruction_class_fns[instruction.instruction_class]['dump'](outfile, instruction, rld)

    @staticmethod
    def validate_instruction(instruction):
        ic = InstructionClass.instruction_class_fns[instruction.instruction_class]
        operand_types = ic['operand_types']
        assert len(instruction.operands) == len(operand_types)
        for i, operand_type in enumerate(operand_types):
            assert isinstance(instruction.operands[i], operand_type)




# TODO: Check this table is complete and correct
# TODO: I suspect I won't want most of the things in here eventually, but for now I am avoiding removing anything and just adding stuff. Review this later and get rid of unwanted stuff.
# TODO: Reorder the "members" so they always appear in consistent order with 'opcode' and 'class' first
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
    0x54: {'opcode': 'CALL', 'class': InstructionClass.ABSOLUTE},
    0x56: {'opcode': 'ICAL', 'class': InstructionClass.IMPLIED},
    0x58: {'opcode': 'ENTER', 'class': InstructionClass.IMMEDIATE2},
    0x5c: {'opcode': 'RET', 'class': InstructionClass.IMPLIED, 'terminator': True},
    0x5a: {'opcode': 'LEAVE', 'class': InstructionClass.IMMEDIATE1, 'terminator': True},
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

class Instruction(ComparisonMixin):
    CONDITIONAL_BRANCH_PAIRS = (
        opcode['BREQ'],  opcode['BRNE'], 
        opcode['BRFLS'], opcode['BRTRU'], 
        opcode['BRGT'],  opcode['BRLT'])

    def __init__(self, opcode, operands = None):
        self.set(opcode, operands)

    # SFTODO: Very few actual uses of this - is this because this approach of allowing an instruction to be changed in-place isn't useful, or because I just haven't got round to tweaking all the code which could benefit from this so it no longer needs to use index-base loops?
    def set(self, opcode_or_instruction, operands = None):
        """Set the Instruction to something else, either a copy of another Instruction or an
        (opcode, operands) pair."""
        if isinstance(opcode_or_instruction, Instruction):
            assert operands is None
            instruction = opcode_or_instruction
            self._opcode = instruction._opcode
            self._operands = instruction.operands
        else:
            assert operands is None or isinstance(operands, list)
            if isinstance(opcode_or_instruction, str):
                self._opcode = opcode[opcode_or_instruction]
            else:
                assert isinstance(opcode_or_instruction, int)
                self._opcode = opcode_or_instruction
            self._operands = operands if operands is not None else []
        InstructionClass.validate_instruction(self)

    # opcode and operands are implemented with setters so we can validate the instruction
    # after updates; in cases where both need to be changed simultaneously set() must be
    # used.

    @property
    def opcode(self):
        return self._opcode

    @opcode.setter
    def opcode(self, value):
        self._opcode = value
        InstructionClass.validate_instruction(self)

    @property
    def operands(self):
        return self._operands

    @operands.setter
    def operands(self, value):
        self._operands = value
        InstructionClass.validate_instruction(self)

    def keys(self):
        return (self.opcode, self.operands)

    def is_a(self, *mnemonics): # SFTODO: Use this everywhere appropriate - I don't like the name so can maybe think of a better one, but want something short as 'is' alone is a reserved word
        return any(self.opcode == opcode[mnemonic] for mnemonic in mnemonics)

    def is_target(self):
        return self.opcode == TARGET_OPCODE

    # SFTODO: CONFUSING THAT THIS DOESN'T EXACTLY MATCH INSTRUCTIONCLASS.BRANCH? RENAME
    # THIS FN? is_control_transfer()? BUT NOT EXACTLY SHORT...
    def is_branch(self):
        return self.instruction_class in (InstructionClass.BRANCH, InstructionClass.SEL)

    def is_paired_conditional_branch(self):
        return self.opcode in self.CONDITIONAL_BRANCH_PAIRS

    def invert_condition(self):
        assert self.is_paired_conditional_branch()
        i = self.CONDITIONAL_BRANCH_PAIRS.index(self.opcode)
        self._opcode = self.CONDITIONAL_BRANCH_PAIRS[i ^ 1]

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
        return opdict[self.opcode].get('terminator', False)

    def has_side_effects(self):
        """Return True if the instruction might access a hardware address"""
        if not (self.is_load() or self.is_store() or self.is_dup_store()):
            return False
        if self.instruction_class == InstructionClass.IMPLIED:
            # Loads/stores which take addresses from the stack could access any address,
            # so we play it safe and assume they have side effects.
            return True
        return self.instruction_class in (InstructionClass.ABSOLUTE,) and any(is_hardware_address(address) for address in self.memory())

    @property
    def instruction_class(self):
        return opdict[self.opcode]['class']

    def add_dependencies(self, dependencies):
        if self.instruction_class == InstructionClass.ABSOLUTE:
            self.operands[0].add_dependencies(dependencies)
            
    def replace_targets(self, alias_dict):
        if self.instruction_class == InstructionClass.BRANCH:
            self.operands[0] = replace_targets(self.operands[0], alias_dict)
        elif self.instruction_class == InstructionClass.SEL:
            self.operands[0] = replace_targets(self.operands[0], alias_dict)
        elif self.instruction_class == InstructionClass.CASE_BLOCK:
            self.operands[0].replace_targets(alias_dict)

    def replace_absolute_address(self, old, new):
        assert isinstance(old, AbsoluteAddress)
        assert isinstance(new, AbsoluteAddress)
        if self.instruction_class in (InstructionClass.ABSOLUTE,):
            if self.operands[0] == old:
                self.operands[0] = new

    def add_targets_used(self, targets_used):
        if self.instruction_class in (InstructionClass.BRANCH, InstructionClass.SEL, InstructionClass.CASE_BLOCK):
            self.operands[0].add_targets_used(targets_used)

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
        # SFTODO TCO WOULD LIKE THIS BUT IT'S AWKWARD W CURRENT DECOMPOSITION INTO PYTHON
        # MODULES assert isinstance(labelled_blob, LabelledBlob)
        self.labels = labelled_blob.labels.get(0, [])
        for label in self.labels:
            label.set_owner(self)
        if len(self.labels) > 0:
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



def is_hardware_address(address):
    # A Label or ExternalReference can never refer to hardware addresses, only memory
    # allocated by the PLASMA compiler, so only FixedAddress operands can reference
    # hardware addresses.
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







# TODO: It would be nice if we had the *option* to output binary rather than ACME
# assembler; I don't think this would be that hard and it might be quite satisfying to
# implement, but for the moment there's enough scope for bugs to cause subtle misbehaviour
# and I think it's best to avoid this temptation for now.
