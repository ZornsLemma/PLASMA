from __future__ import print_function
import fileinput
import sys



# Despite the comments in the README, looking at the code shows that SUB does
# (next from top)-top. 

# When we build a tree node from a two-argument opcode, we make the topmost
# argument the first child of our tree nodes. This has the minor advantage that
# any "UNKNOWN" nodes should stay together at the front (TODO: I think).


# TODO: Note that my idea of optimising directly on bytecode modules is great,
# *except* that the bytecode included in the PLASMA/PLAS128 binaries doesn't
# (currently; this might be changeable, I think that Apple II VM does work like
# that) get compiled to a module, so it then couldn't be optimised.

# TODO: It may not fit neatly into the current framework, but if we have
# repeated CB/CW instructions, we could optimised all but the first into DUP
# instructions (which are 1-2 bytes shorter)

# TODO: I don't know if it ever happens, but if we have a store followed by a
# load fom the same address, we could optimise by changing STORE:LOAD into
# DUP:STORE. This doesn't fit well with the current framework as stores aren't
# in the node tree, but it would be trivial for a peephole optimiser to do on
# the serialised output. (There is an instance of this towards the end of
# readfile() in 32cmd.a.)

# TODO: I am getting the idea that the tree-based optimisation is good for some
# things, but some optimisations would be better done on the serialised output
# - and ideally (obviously not if a label intervenes) this is done on the whole
# serialised output, not on little chunks.

# TODO: NOT+BRFLS can be replaced by BRTRU and vice versa

def remove_square_brackets(s):
    assert s[0] == '['
    assert s[-1] == ']'
    return s[1:-1]


def multi_opcode(opcode, operands):
    assert len(operands) > 0
    if len(operands) == 1:
        return operands[0]
    else:
        node = Node([opcode])
        node.children = [operands[0], multi_opcode(opcode, operands[1:])]
        return node

class Node:
    def __init__(self, instruction):
        assert type(instruction) == list
        self.instruction = instruction
        self.children = []

    def dump(self, level = 0):
        print('  '*level + ' '.join(self.instruction))
        for child in self.children:
            child.dump(level + 1)

    # TODO: I think I will need a concept of "unknown value" - this will allow
    # the emulated stack to be initialised on function entry (with the number
    # of function parameters) or after a CALL (with a single value). (CALL,
    # incidentally, will have to force a fresh start - we have no way to know
    # how many arguments CALL consumes. So we would be able to optimise the
    # instructions between CALLs, but not the CALLs themselves.)

    # TODO: We probably need to repeat this more than once, as I think some
    # optimisations both depend on (e.g.) const folding of children, and in
    # turn make more const folding possible. But I may have managed to avoid
    # this, not sure, think about it.

    # TODO: I think this needs to be much more reticent about making changes
    # where there are UNKNOWN values in the tree. (That's what they're there
    # for...)
    def optimise(self):
        for child in self.children:
            child.optimise()

        # This will optimise CB to itself, but that's harmless, and it's useful
        # to do this processing for CW, as it may allow us to switch to CB if
        # the operand is byte-sized.
        if (self.can_evaluate() and 
            all(child.is_constant() for child in self.children)):
            value = self.evaluate()
            if value == 0:
                self.instruction = ['ZERO']
            elif value > 0 and value <= 255:
                self.instruction = ['CB', str(value)]
            else:
                self.instruction = ['CW', str(value)]
            self.children = []

        # If only one child is constant, we try to arrange for that to be the
        # first child. This is helpful for other optimisations, and (I
        # think) minimises stack use, since the constant only occupies a stack
        # slot once the calculation of the non-constant (which may use many
        # stack locations before collapsing down to one) is complete. If both
        # are constant and one constant is 2, we switch that to the first
        # child to open up possibilities for using IDXW.
        assert len(self.children) <= 2
        if self.is_commutative() and len(self.children) == 2:
            if self.children[1].is_constant():
                if (not self.children[0].is_constant() or
                    self.children[1].evaluate() == 2):
                        self.children[0], self.children[1] = self.children[1], self.children[0]

        # If this operation is associative (TODO: we just use the 'commutative'
        # property for now, as I am not sure we have any which are one but not
        # the other, but think about it) and one or both of its children are
        # the same operation, we can swap the children around - this may allow
        # more constant folding. TODO: I may *actually* require commutativity
        # here
        # TODO: Do we actually need the recursive nature of
        # same_opcode_operand_set() here? Hard to think about it right now, but
        # the fact that we always optimise child nodes first might mean that
        # this isn't necessary.
        if self.is_commutative():
            s = self.same_opcode_operand_set(self.instruction[0])
            s_constant = [node for node in s if node.is_constant()]
            s_nonconstant = [node for node in s if not node.is_constant()]
            if len(s_constant) >= 2:
                # The order in the next line is important; this pushes the
                # constant operands down the tree, keeping them together, so
                # they can be constant folded.
                s = s_nonconstant + s_constant                                  
                self.children = [s[0], multi_opcode(self.instruction[0], s[1:])]
                for child in self.children:
                    child.optimise()

        # Adding 1 can be accomplished via INCR.
        if (self.instruction[0] == 'ADD' and
            self.children[0].is_constant() and
            self.children[0].evaluate() == 1):
            self.instruction[0] = 'INCR'
            del self.children[0]

        # Subtracting 1 can be accomplished via DECR.
        if (self.instruction[0] == 'SUB' and
            self.children[0].is_constant() and
            self.children[0].evaluate() == 1):
            self.instruction[0] = 'DECR'
            del self.children[0]

        # 'CB 2:MUL:ADD' == 'IDXW' TODO: Possibly we should expand IDXW out at
        # some earlier point, to open up constant folding opportunities? This
        # might obviate/improve on the need for the optimisation below.
        if (self.instruction[0] == 'ADD' and
            self.children[0].instruction[0] == 'MUL' and
            self.children[0].children[0].is_constant() and
            self.children[0].children[0].evaluate() == 2):
            self.instruction = ['IDXW']
            self.children[0] = self.children[0].children[1]

        # If we're adding (TODO: or subtracting) a constant to the result of an
        # IDXW which has a constant base address, we can fold our constant into
        # it. 
        if (self.instruction[0] == 'ADD' and 
            self.children[0].is_constant() and
            self.children[1].instruction[0] == 'IDXW' and
            self.children[1].children[1].is_constant()):
            self.instruction = self.children[1].instruction
            new_children = self.children[1].children
            new_children[1].instruction[1] = str((new_children[1].evaluate() + self.children[0].evaluate() & 0xfff))
            self.children = new_children

        # LLW [n]:CB 8:SHR can be replaced by LLB [n+1] TODO: There are
        # probably similar optimisations for other opcodes
        if (self.instruction[0] == 'SHR' and
            self.children[0].is_constant() and
            self.children[0].evaluate() == 8 and
            self.children[1].instruction[0] == 'LLW'):
            self.instruction = ['LLB', '[' + str(int(remove_square_brackets(self.children[1].instruction[1])) + 1) + ']']
            self.children = []




    # Given an opcode like "MUL", this pulls out all the nodes
    # which are being multiplied together, flattening out any nested MUL nodes.
    def same_opcode_operand_set(self, opcode):
        if self.instruction[0] == opcode:
            result = []
            for child in self.children:
                result.extend(child.same_opcode_operand_set(opcode))
            return result
        else:
            return [self]



                

    def is_constant(self):
        info = opcodes[self.instruction[0]]
        return info.has_key('constant') and info['constant']

    def is_commutative(self):
        # TODO: This should probably return False *if* any of the children
        # (direct or indirect) are the proposed 'unknown value' nodes
        info = opcodes[self.instruction[0]]
        return info.has_key('commutative') and info['commutative']

    def can_evaluate(self):
        info = opcodes[self.instruction[0]]
        return (all(child.is_constant() for child in self.children) and
                info.has_key('evaluate_fn'))

    def evaluate(self):
        assert self.can_evaluate()
        value = opcodes[self.instruction[0]]['evaluate_fn'](self)
        value = value & 0xffff
        return value

    def serialise(self):
        instructions = []
        for child in self.children[::-1]:
            instructions.extend(child.serialise())
        instructions.append(self.instruction)
        return instructions



def die(error):
    print(error, file=sys.stderr)
    sys.exit(1)



# instructions should be a straight-line sequence of instructions, i.e. no
# branches or labels.
def tree(instructions):
    stack = []
    # UNKNOWN nodes are only numbered for debugging; this allows us to see
    # that they are not re-ordered.
    unknown_count = 0
    for instruction in instructions:
        # TODO: Nasty hack to make us accept either a string or a
        # pre-split list
        if type(instruction) == list:
            s = instruction
        else:
            s = instruction.split()
        opcode = s[0]
        opcode_info = opcodes[opcode]
        node = Node(s)
        arguments = []
        for i in range(opcode_info['consume']):
            if stack:
                node.children.append(stack.pop())
            else:
                node.children.append(Node(['UNKNOWN', str(unknown_count)]))
                unknown_count += 1
        assert opcode_info['produce'] <= 1
        if opcode_info['produce'] == 1:
            stack.append(node)
    return stack



# TODO: We need to add support for evaluating many of these operations
opcodes = {
    'CB':  { 'byte' : 0x2a, 'consume' : 0, 'produce' : 1, 'constant' : True,
        'evaluate_fn' : lambda node : int(node.instruction[1]) },
    'CW':  { 'byte' : 0x2c, 'consume' : 0, 'produce' : 1, 'constant' : True,
        'evaluate_fn' : lambda node : int(node.instruction[1]) },
    'ADD': { 'byte' : 0x02, 'consume' : 2, 'produce' : 1, 'commutative' : True,
        'evaluate_fn' : lambda node : node.children[0].evaluate() +
        node.children[1].evaluate()},
    'SUB': { 'byte' : 0x04, 'consume' : 2, 'produce' : 1, 
        'evaluate_fn' : lambda node : node.children[1].evaluate() - node.children[0].evaluate() },
    'MUL': { 'byte' : 0x06, 'consume' : 2, 'produce' : 1, 'commutative' : True,
        'evaluate_fn' : lambda node : node.children[0].evaluate() * node.children[1].evaluate() },
    'SHR': { 'byte' : 0x1c, 'consume' : 2, 'produce' : 1},
    'SHL': { 'byte' : 0x1a, 'consume' : 2, 'produce' : 1},
    'AND': { 'byte' : 0x14,'consume' : 2, 'produce' : 1},
    'LAND': { 'byte' : 0x24, 'consume' : 2, 'produce' : 1},
    'LOR': { 'byte' : 0x22, 'consume' : 2, 'produce' : 1},
    'IOR': { 'byte' : 0x16, 'consume' : 2, 'produce' : 1},
    'XOR': { 'byte' : 0x18, 'consume' : 2, 'produce' : 1},
    'NOT': { 'byte' : 0x20, 'consume' : 1, 'produce' : 1},
    'NEG': { 'byte' : 0x10, 'consume' : 1, 'produce' : 1},
    'ISEQ': { 'byte' : 0x40, 'consume' : 2, 'produce' : 1},
    'ISNE': { 'byte' : 0x42, 'consume' : 2, 'produce' : 1},
    'ISGT': { 'byte' : 0x44, 'consume' : 2, 'produce' : 1},
    'ISGE': { 'byte' : 0x48, 'consume' : 2, 'produce' : 1},
    'ISLE': { 'byte' : 0x4a, 'consume' : 2, 'produce' : 1},
    'ISLT': { 'byte' : 0x46, 'consume' : 2, 'produce' : 1},
    'IDXB': { 'byte' : 0x02, 'consume' : 2, 'produce' : 1},
    'IDXW': { 'byte' : 0x1e, 'consume' : 2, 'produce' : 1},
    'LB':  { 'byte' : 0x60, 'consume' : 1, 'produce' : 1},
    'LA':  { 'byte' : 0x26, 'consume' : 1, 'produce' : 1, 'arguments' : 1},
    'LAB':  { 'byte' : 0x68, 'consume' : 1, 'produce' : 1, 'arguments' : 1},
    'LAW':  { 'byte' : 0x6a, 'consume' : 1, 'produce' : 1, 'arguments' : 1},
    'LW':  { 'byte' : 0x62, 'consume' : 1, 'produce' : 1},
    'LLA':  { 'byte' : 0x28, 'consume' : 0, 'produce' : 1},
    'LLB':  { 'byte' : 0x64, 'consume' : 0, 'produce' : 1},
    'LLW':  { 'byte' : 0x66, 'consume' : 0, 'produce' : 1},
    'INCR':  { 'byte' : 0x0c, 'consume' : 1, 'produce' : 1},
    'DECR':  { 'byte' : 0x0e, 'consume' : 1, 'produce' : 1},
    'UNKNOWN' : { 'consume' : 0, 'produce': 1},
    'ZERO': { 'byte' : 0x00, 'consume' : 0, 'produce' : 1, 'constant' : True,
        'evaluate_fn': lambda node: 0},
    'CS' : { 'byte' : 0x2e, 'consume' : 0, 'produce' : 1, 'arguments' : 999 },
    'CALL' : { 'byte' : 0x54, 'branch' : True, 'arguments' : 1 },
    'ICAL' : { 'byte' : 0x56, 'branch' : True },
    'BRFLS' : { 'byte' : 0x4c, 'branch' : True, 'arguments' : 1 },
    'BRNCH' : { 'byte' : 0x50, 'branch' : True, 'arguments' : 1 },
    'BRGT' : { 'byte' : 0x38, 'branch' : True, 'arguments' : 1 },
    'BRNE' : { 'byte' : 0x3e, 'branch' : True, 'arguments' : 1 },
    'RET' : { 'byte' : 0x5c, 'branch' : True },
    # TODO: DROP is temporarily marked as branch=True; it can actually be
    # handled as part of a sequence of straight line instructions but needs a
    # bit of special handling so I'm postponing that for now.
    'DROP' : { 'byte' : 0x30, 'branch' : True, 'consume' : 1, 'produce' : 0 },
    'DUP' : { 'byte' : 0x32, 'branch' : True },
    'ENTER' : { 'byte' : 0x58, 'branch' : True },
    'LEAVE' : { 'byte' : 0x5a, 'branch' : True },
    'SLB' : { 'byte' : 0x74, 'branch' : True },
    'DLB' : { 'byte' : 0x6c, 'branch' : True },
    'DLW' : { 'byte' : 0x6e, 'branch' : True },
    'DAB' : { 'byte' : 0x7c, 'branch' : True, 'arguments' : 1 },
    'DAW' : { 'byte' : 0x7e, 'branch' : True, 'arguments' : 1 },
    'SLW' : { 'byte' : 0x76, 'branch' : True},
    'SAW' : { 'byte' : 0x7a, 'branch' : True, 'arguments' : 1 },
    'SB' : { 'byte' : 0x70, 'branch' : True },
    'SW' : { 'byte' : 0x72, 'branch' : True },
    'SAB' : { 'byte' : 0x78, 'branch' : True, 'arguments' : 1 },
    'LABEL': { 'branch' : True },
}



# TODO!?
def test():
    #instructions = ['CW 1000', 'LW', 'CB 2', 'CW 3', 'CW 5', 'SUB', 'CW 10', 'ADD', 'CW 1001', 'LW', 'ADD', 'MUL', 'ADD']
    #instructions = ['CW 1000', 'LW', 'CW 10', 'SUB']
    #instructions = ['CW 1000', 'LW', 'CB 5', 'MUL', 'CB 4', 'MUL']
    #instructions = ['CW 5', 'CW 6', 'ADD', 'ADD']
    #instructions = ['CW 5', 'ADD', 'ADD', 'ZERO', 'MUL']
    instructions = [
        'CB 1',
        'CB 2',
        'CB 16',
        'LLW [0]',
        'LB',
        'SUB',
        'MUL',
        'CB 2',
        'ADD',
        'ZERO',
        'ADD',
        'ADD']
    node = tree(instructions)
    assert len(node) == 1
    node = node[0]
    print('Before:\n')
    node.dump()
    print('\nAfter:\n')
    node.optimise()
    node.dump()
    print('\nSerialised:\n')
    print(node.serialise())


def optimise(instructions):
    # TODO print("OPTIMISE ENTER: " + repr(instructions))
    new_instructions = []
    if len(instructions) > 0:
        nodes = tree(instructions)
        for node in nodes:
            node.optimise()
            instructions = node.serialise()
            new_instructions.extend(instructions)
    # TODO print("OPTIMISE EXIT: " + repr(new_instructions))
    return [instruction for instruction in  new_instructions if instruction[0] != 'UNKNOWN']

def emit(instructions):
    # Spit the instructions out again, taking pains to make the output
    # near-identical to the input for minimal pain diffing.
    for instruction in instructions:
        opcode = instruction[0]
        if opcode in ('COMMENT', 'LABEL'):
            print(instruction[1])
            continue
        info = opcodes[opcode]
        if opcode == 'UNKNOWN':
            continue
        #print(instruction) # TODO TEMP
        opcode_byte = info['byte']
        if opcode == 'CS':
            print("\t!BYTE\t$%02X\t\t\t; %s" % (opcode_byte, opcode))
            length = int(instruction[1])
            print("\t!BYTE\t$%02X" % length)
            i = 2
            while length > 0:
                print("\t!BYTE\t%s" % instruction[i])
                length -= instruction[i].count('$')
                assert length >= 0
                i += 1
        elif info.has_key('arguments') and info['arguments']:
            print("\t!BYTE\t$%02X\t\t\t; %s\t%s" % (opcode_byte, opcode, instruction[1]))
            if instruction[-2]:
                padded_label = (instruction[-2] + "   ")[:6]
                print("%s\t!WORD\t%s\t\t" % (padded_label, instruction[-1]))
            else:
                print("\t!WORD\t%s" % instruction[-1])
        elif opcode == 'CB':
            print("\t!BYTE\t$%02X,$%02X\t\t\t; %s\t%s" % (opcode_byte, int(instruction[1]), opcode, instruction[1]))
        elif opcode == 'CW':
            value = int(instruction[1])
            print("\t!BYTE\t$%02X,$%02X,$%02X\t\t; %s\t%s" % (opcode_byte, value & 0xff, (value & 0xff00) >> 8, opcode, value))
        elif opcode in ('LLA', 'LLB', 'LLW', 'SLB', 'SLW', 'DLB', 'DLW'):
            value = remove_square_brackets(instruction[1])
            print("\t!BYTE\t$%02X,$%02X\t\t\t; %s\t%s" % (opcode_byte, int(value), opcode, instruction[1]))
        elif opcode == 'ENTER':
            s = instruction[1].split(',')
            a = int(s[0])
            b = int(s[1])
            print("\t!BYTE\t$%02X,$%02X,$%02X\t\t; %s\t%s" % (opcode_byte, a, b, opcode, instruction[1]))
        else:
            #assert len(instructions) == 1
            print("\t!BYTE\t$%02X\t\t\t; %s" % (opcode_byte, opcode))


# TODO: We probably need to repeatedly call this until it stops changing the
# size of function_body
def peephole_optimise(function_body):
    new_body = []
    i = -1
    while i + 1 < len(function_body):
        i += 1

        # Get this instruction; if it's a COMMENT or a LABEL, just pass it
        # through
        this_instruction = function_body[i]
        if this_instruction[0] in ('COMMENT', 'LABEL'):
            new_body.append(this_instruction)
            continue

        # Get the next instruction, ignoring any number of COMMENT 'instructions'
        j = i
        pending_comments = []
        while True:
            j += 1
            if j == len(function_body):
                next_instruction = ['LABEL']
                break
            next_instruction = function_body[j]
            if next_instruction[0] == 'COMMENT':
                pending_comments.append(next_instruction)
            else:
                break

        # If the next instruction is a LABEL, we can't optimise across it, so
        # just pass the current instruction through.
        if next_instruction[0] == 'LABEL':
            new_body.append(this_instruction)
            continue

        # OK, we have two consecutive instructions (possibly with comments in
        # between).

        # If we save and then load from the same address, we can use the
        # corresponding 'store duplicate' opcode for the store and get rid of
        # the load.
        # TODO: For SAB and SAW, we will be removing a relocation on
        # next_instruction here; currently the output will fail to assemble.
        if (this_instruction[0] in ('SLB', 'SLW', 'SAB', 'SAW') and
            next_instruction[0] == 'L'+this_instruction[0][1:] and
            this_instruction[1] == next_instruction[1]):
            new_body.append(['D'+this_instruction[0][1:]] + this_instruction[1:])
            new_body.extend(pending_comments)
            i = j
            continue

        # The second of two identical loads can be replaced by a DUP
        # TODO: If there are three in a row, this will replace the second load
        # with a DUP and thereby miss the opportunity to do the third as well.
        # TODO: Have I got all the relevant instructions here?
        if (this_instruction == next_instruction and 
            this_instruction[0] in ('CB', 'CW', 'CS', 'LA', 'LAB', 'LAW', 'LLA', 'LLB', 'LLW')):
            new_body.append(this_instruction)
            new_body.extend(pending_comments)
            new_body.append(['DUP'])
            i = j
            continue

        # Just pass this instruction through if we haven't found anything to
        # improve.
        new_body.append(this_instruction)

    return new_body


def tree_optimise(function_body):
    new_body = []
    instructions = []
    for instruction in function_body:
        opcode = instruction[0]
        if opcode == 'COMMENT':
            new_body.append(instruction)
            continue
        info = opcodes[opcode]
        if info.has_key('branch') and info['branch']:
            if instructions:
                new_body.extend(optimise(instructions))
            new_body.append(instruction)
            instructions = []
            continue
        instructions.append(instruction)

    if instructions:
        new_body.extend(optimise(instructions))
    return new_body


def optimise_function(function_body):
    # TODO: Is this repeated optimisation actually helpful?
    while True:
        l1 = len(function_body)

        while True:
            l2 = len(function_body)
            function_body = peephole_optimise(function_body)
            assert len(function_body) <= l2
            if len(function_body) == l2:
                break

        assert len(function_body) <= l1
        function_body = tree_optimise(function_body)

        assert len(function_body) <= l1
        if len(function_body) == l1:
            break

    emit(function_body)


#test()
#sys.exit(0)


in_function = False
lines = fileinput.input()
line_it = lines.__iter__()
while True:
    try:
        line = line_it.next()
    except StopIteration:
        if function_body:
            optimise_function(function_body)
        break
    line = line[:-1]
    if line.find('JSR\tINTERP') != -1:
        print(line)
        in_function = True
        near_end_function = False
        function_body = []
        continue
    if not in_function:
        print(line)
        continue

    signature1 = '; <stdin>: '
    signature2 = ': end'
    if line[0:len(signature1)] == signature1 and line.strip()[-len(signature2):] == signature2:
        # We need to keep consuming lines which start with a tab; a few
        # bytecodes may follow the comment for the function 'end' line.
        near_end_function = True
    if near_end_function and line[0] != '\t':
        in_function = False
        optimise_function(function_body)
        print(line)
        continue

    if line[0] == ';':
        function_body.append(['COMMENT', line])
        continue

    if line[0] != '\t':
        # We've seen a label
        function_body.append(['LABEL', line])
        continue

    s = line.strip()
    if s.find(';') == 0:
        # It's a comment-only line, so the comment isn't a disassembly. Just
        # pass it through.
        function_body.append(['COMMENT', line])
        continue

    # It's almost certainly an instruction. We just rely on the "disassembly"
    # in the comments.
    instruction = line[line.find(';')+1:].split()
    opcode = instruction[0]
    info = opcodes[opcode]

    # Some instructions take an argument, which appears on the following line
    # along with a (harmless, but valuable) label for fix-up purposes. We take
    # that line now. TODO: The 'arguments' keyword is a bit misnamed; it
    # doesn't apply to every opcode which takes an argument, it applies to ones
    # which take "separate line arguments" in the assembly.
    if info.has_key('arguments') and info['arguments'] > 0:
        if opcode == 'CS':
            cs_length = -1
            while True:
                try:
                    line2 = line_it.next()
                    line2 = line2[:-1]
                except StopIteration:
                    die("Missing argument line")
                line += '\n' + line2
                s = line2.split()
                if cs_length == -1:
                    cs_length = int(s[1][1:], 16)
                    instruction.append(str(cs_length))
                else:
                    instruction.append(s[1])
                    cs_length -= s[1].count('$')
                    assert cs_length >= 0
                if cs_length == 0:
                    break
        else:
            assert info['arguments'] == 1
            try:
                line2 = line_it.next()
                line2 = line2[:-1]
            except StopIteration:
                die("Missing argument line")
            line += '\n' + line2
            label = line2.split('\t')[0]
            value = line2.split('\t')[2]
            assert len(instruction) == 2
            instruction.extend([label, value])

    function_body.append(instruction)
