from __future__ import print_function
import sys



# Taking precedent from SUB, which subtracts next from top from top, if we have
# CW 2:CW 3:SUB (== CW 1), the first child of the SUB node is 3 and the second
# is 2, not the other way around.


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
    # turn make more const folding possible
    def optimise(self):
        for child in self.children:
            child.optimise()

        # This will optimise CB to itself, but that's harmless, and it's useful
        # to do this processing for CW, as it may allow us to switch to CB if
        # the operand is byte-sized.
        if (self.can_evaluate() and 
            all(child.is_constant() for child in self.children)):
            value = self.evaluate()
            if value >= 0 and value <= 255:
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

        # 'CB 2:MUL:ADD' == 'IDXW'
        if (self.instruction[0] == 'ADD' and
            self.children[0].instruction[0] == 'MUL' and
            self.children[0].children[0].is_constant() and
            self.children[0].children[0].evaluate() == 2):
            self.instruction = ['IDXW']
            self.children[0] = self.children[0].children[1]

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
        return (all(child.is_constant() for child in self.children) and
                self.instruction[0] in ('CW', 'CB', 'ADD', 'SUB', 'MUL'))

    def evaluate(self):
        assert self.can_evaluate()
        if self.instruction[0] in ('CW', 'CB'):
            value = int(self.instruction[1])
        elif self.instruction[0] == 'ADD':
            value = self.children[0].evaluate() + self.children[1].evaluate()
        elif self.instruction[0] == 'SUB':
            value = self.children[0].evaluate() - self.children[1].evaluate()
        elif self.instruction[0] == 'MUL':
            value = self.children[0].evaluate() * self.children[1].evaluate()
        else:
            assert False
        value = value & 0xffff
        return value

    def serialise(self):
        for child in self.children[::-1]:
            child.serialise()
        print(' '.join(self.instruction))



def die(error):
    print(error, file=sys.stderr)
    sys.exit(1)



def tree(instructions):
    stack = []
    for instruction in instructions:
        s = instruction.split()
        opcode = s[0]
        opcode_info = opcodes[opcode]
        node = Node(s)
        if len(stack) < opcode_info['consume']:
            die('Stack underflow')
        arguments = []
        for i in range(opcode_info['consume']):
            node.children.append(stack.pop())
        assert opcode_info['produce'] <= 1
        if opcode_info['produce'] == 1:
            stack.append(node)
    assert len(stack) == 1 # TODO: don't assert, bad input could cause this
    return stack[0]



opcodes = {
    'CB':  { 'consume' : 0, 'produce' : 1, 'constant' : True },
    'CW':  { 'consume' : 0, 'produce' : 1, 'constant' : True },
    'ADD': { 'consume' : 2, 'produce' : 1, 'commutative' : True },
    'SUB': { 'consume' : 2, 'produce' : 1},
    'MUL': { 'consume' : 2, 'produce' : 1, 'commutative' : True },
    'LW':  { 'consume' : 1, 'produce' : 1}
}



#instructions = ['CW 1000', 'LW', 'CB 2', 'CW 3', 'CW 5', 'SUB', 'CW 10', 'ADD', 'CW 1001', 'LW', 'ADD', 'MUL', 'ADD']
#instructions = ['CW 1000', 'LW', 'CW 10', 'SUB']
instructions = ['CW 1000', 'LW', 'CB 5', 'MUL', 'CB 4', 'MUL']
node = tree(instructions)
print('Before:\n')
node.dump()
print('\nAfter:\n')
node.optimise()
node.dump()
print('\nSerialised:\n')
node.serialise()
