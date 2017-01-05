from __future__ import print_function
import sys



class Node:
    def __init__(self, instruction):
        assert type(instruction) == list
        self.instruction = instruction
        self.children = []

    def dump(self, level = 0):
        print('  '*level + ' '.join(self.instruction))
        for child in self.children:
            child.dump(level + 1)

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

    def is_constant(self):
        assert type(self.instruction) == list
        info = opcodes[self.instruction[0]]
        return info.has_key('constant') and info['constant']

    def can_evaluate(self):
        return (all(child.is_constant() for child in self.children) and
                self.instruction[0] in ('ADD', 'CW', 'CB'))

    def evaluate(self):
        assert self.can_evaluate()
        if self.instruction[0] in ('CW', 'CB'):
            value = int(self.instruction[1])
        elif self.instruction[0] == 'ADD':
            value = sum(child.evaluate() for child in self.children)
        else:
            assert False
        value = value & 0xffff
        return value



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
    'ADD': { 'consume' : 2, 'produce' : 1 }
}



instructions = ['CW 5', 'CW 4', 'ADD', 'CW 10', 'ADD']
node = tree(instructions)
print('Before:\n')
node.dump()
print('\nAfter:\n')
node.optimise()
node.dump()
