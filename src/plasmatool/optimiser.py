import itertools

from bytecode import *
from utils import bidict

# TODO: Possibly most of the classes/functions in this file should be named with a single
# leading underscore; the only "public" function in here is optimise().

# SFTODO TEMPORARY (?) PSEUDO-CTOR FOR TRANSITION
# SFTODO: IF THIS LIVES SHOULD IT BE IN plasma.py?
def NopInstruction():
    return Instruction(NOP_OPCODE, [])

# Helper class used to chop up a bytecode function in blocks.
class FunctionSplitter(object):
    def __init__(self, bytecode_function):
        self.ops = bytecode_function.ops
        self.blocks_metadata = [None]
        self.block_starts = [0]

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



# Remove all but the first of each group of consecutive targets; this makes it easier to spot other
# optimisations.
def target_deduplicate(bytecode_function):
    alias = {}
    new_ops = []
    previous_instruction = None
    changed = False
    for instruction in bytecode_function.ops:
        if instruction.is_target() and previous_instruction and previous_instruction.is_target():
            alias[instruction.operands[0]] = previous_instruction.operands[0]
            changed = True
        else:
            previous_instruction = instruction
            new_ops.append(instruction)
    for instruction in new_ops:
        instruction.replace_targets(alias)
    bytecode_function.ops = new_ops
    return changed


# Remove a BRNCH to an immediately following target.
def branch_optimise(bytecode_function):
    changed = False
    new_ops = []
    for i, instruction in enumerate(bytecode_function.ops):
        # SFTODO: WOULD IT BE WORTH HAVING A next_instruction HELPER FN WHICH RETURNS A NOP (INSTEAD OF NONE) IF WE WOULD INDEX OFF THE END? THAT WOULD SLIGHTLY SIMPLIFY THE FOLLOWING LINE AS WE COULD OMIT THE NONE CHECK AND MAY HELP OTHER FNS...
        next_instruction = None if i == len(bytecode_function.ops)-1 else bytecode_function.ops[i+1]
        if not (instruction.is_a('BRNCH') and next_instruction and next_instruction.is_target() and instruction.operands[0] == next_instruction.operands[0]):
            new_ops.append(instruction)
        else:
            changed = True
    bytecode_function.ops = new_ops
    return changed


def build_target_dictionary(bytecode_function, test):
    result = {}
    for i in range(len(bytecode_function.ops)-1):
        if bytecode_function.ops[i].is_target() and test(bytecode_function.ops[i+1]):
            result[bytecode_function.ops[i].operands[0]] = bytecode_function.ops[i+1]
    return result



# This replaces a BRNCH to a LEAVE or RET with the LEAVE or RET itself.
# SFTODO: Not just in this function - I am a bit inconsistent with opcode meaning "BRNCH" and opcode meaning 0x50 - perhaps check terminology, but I think opcode should be a hex value (so the opcode reverse dict is fine, because it gives us the opcode for a name, it's the 'opcode' member of the subdicts in opdict that are wrong, among others)
def branch_optimise2(bytecode_function):
    changed = False
    targets = build_target_dictionary(bytecode_function, lambda instruction: instruction.is_a('LEAVE', 'RET'))
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
    targets = build_target_dictionary(bytecode_function, lambda instruction: instruction.is_a('BRNCH'))
    alias = {k:v.operands[0] for k, v in targets.items()}
    for instruction in bytecode_function.ops:
        original_operands = instruction.operands[:] # SFTODO EXPERIMENTAL - THIS IS NOW WORKING, BUT I'D RATHER NOT HAVE TO DO THIS
        instruction.replace_targets(alias)
        changed = changed or (original_operands != instruction.operands)
    return changed

# Remove targets which have no instructions referencing them; this can occur as a result
# of other optimisations and is useful in opening up further optimisations.
def remove_orphaned_targets(bytecode_function):
    changed = False
    targets_used = set()
    for instruction in bytecode_function.ops:
        instruction.add_targets_used(targets_used)
    new_ops = []
    for instruction in bytecode_function.ops:
        if not (instruction.is_target() and instruction.operands[0] not in targets_used):
            new_ops.append(instruction)
        else:
            changed = True
    bytecode_function.ops = new_ops
    return changed

# Remove unreachable code; this works in conjunction with remove_orphaned_targets().
def remove_dead_code(bytecode_function):
    blocks, block_metadata = get_target_terminator_blocks(bytecode_function)
    block_reachable = [i == 0 or x is not None for i, x in enumerate(block_metadata)]
    bytecode_function.ops = list(itertools.chain.from_iterable(itertools.compress(blocks, block_reachable)))
    return not all(block_reachable)

# A CASEBLOCK instruction is followed by the 'otherwise' instructions. If the 'otherwise'
# instructions end with a terminator, the CASEBLOCK+otherwise instructions form an isolated
# block which can be moved around freely. If such a block is preceded by a BRNCH, we move it
# to the end of the function - this may allow the BRNCH to be optimised away. (It would be
# correct and mostly harmless to move *any* isolated CASEBLOCK+otherwise instruction block to
# the end of the function, but it would introduce unnecessary differences between the input
# and output.)
def move_case_blocks(bytecode_function):
    blocks, block_target = get_target_terminator_blocks(bytecode_function)
    new_ops = []
    tail = []
    for i, block in enumerate(blocks):
        if block_target[i] and len(block) > 1 and block[1].opcode == CASE_BLOCK_OPCODE and block[-1].is_terminator() and blocks[i-1][-1].is_a('BRNCH'):
            tail.extend(block)
        else:
            new_ops.extend(block)
    new_ops.extend(tail)
    changed = bytecode_function.ops != new_ops 
    bytecode_function.ops = new_ops
    return changed




# SFTODO: In following fns and their callers, should I stop saying 'metadata' and say
# 'target', because that's what it is in these cases? It may turn out that FunctionSplitter() is used
# in cases where the metadata is something else, so that's fine, but the below do
# specifically use targets.


# SFTODO: EXPERIMENTAL - SEEMS QUITE PROMISING, TRY USING THIS IN block_move() AND THEN OTHERS
# SFTODO: THIS IS QUITE SIMILAR TO THE LOCAL get_blocks FUNCTION ELSEWHERE
def get_target_terminator_blocks(bytecode_function):
    foo = FunctionSplitter(bytecode_function)
    for i, instruction in enumerate(bytecode_function.ops):
        if instruction.is_target():
            foo.start_before(i, instruction.operands[0])
        elif instruction.is_terminator():
            foo.start_after(i, None)
    return foo.get_blocks_and_metadata()

# Split a function up into blocks such that:
# - targets only appear as the first instruction in a block
# - terminators only appear as the last instruction in a block
# A list of boolean values is also generated indicating whether a block is "isolated" or not; an isolated block can only be entered via a branch to its target and ends with a terminator.
def get_target_terminator_blocks_with_isolated_flag(bytecode_function): # SFTODO POOR NAME
    blocks, blocks_metadata = get_target_terminator_blocks(bytecode_function)
    block_isolated = [False] * len(blocks)
    for i, block in enumerate(blocks):
        if not block[-1].is_terminator():
            blocks_metadata[i] = None
        else:
            block_isolated[i] = i > 0 and blocks[i-1][-1].is_terminator()
    return blocks, blocks_metadata, block_isolated

def block_deduplicate(bytecode_function):
    blocks, blocks_metadata, block_isolated = get_target_terminator_blocks_with_isolated_flag(bytecode_function)

    # Compare each pair of non-anonymous blocks (ignoring the initial target
    # instruction); if two are identical and one of them is never entered by falling
    # through from the previous block, we can delete that one and replace all
    # references to its target with the target of the other block.
    alias = {}
    unwanted = set()
    for i in range(len(blocks)):
        for j in range(i+1, len(blocks)):
            if blocks_metadata[i] and blocks_metadata[j] and blocks[i][1:] == blocks[j][1:]:
                assert blocks[i][0].is_target()
                assert blocks[j][0].is_target()
                if not (blocks_metadata[i] in unwanted or blocks_metadata[j] in unwanted):
                    replace = None
                    if block_isolated[i]:
                        replace = (blocks_metadata[i], blocks_metadata[j])
                    elif block_isolated[j]:
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
                instruction.replace_targets(alias)
                new_ops.append(instruction)
        else:
            changed = True
    bytecode_function.ops = new_ops

    return changed


# Look for blocks of code within a function which cannot be entered except via their
# target and see if we can move those blocks to avoid the need to BRNCH to them.
def block_move(bytecode_function):
    # In order to avoid gratuitously moving chunks of code around (which makes it
    # harder to verify the transformations performed by this function are valid), we remove any
    # redundant branches to the immediately following instruction first.
    changed = branch_optimise(bytecode_function)

    blocks, blocks_metadata, block_isolated = get_target_terminator_blocks_with_isolated_flag(bytecode_function)

    # Merge blocks where possible.
    for i, block in enumerate(blocks):
        if len(block) > 0 and block[-1].is_a('BRNCH'):
            target = block[-1].operands[0]
            if target in blocks_metadata:
                target_block_index = blocks_metadata.index(target)
                if target_block_index != i and block_isolated[target_block_index]:
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

def peephole_optimise(bytecode_function):
    changed = False
    i = 0
    bytecode_function.ops += [NopInstruction(), NopInstruction()] # add dummy NOPs so we can use ops[i+2] freely
    dup_for_store = {opcode['SAW']: opcode['DAW'],
                     opcode['SAB']: opcode['DAB'],
                     opcode['SLB']: opcode['DLB'],
                     opcode['SLW']: opcode['DLW']}
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
        elif instruction.is_paired_conditional_branch() and next_instruction.is_a('BRNCH') and next_next_instruction.is_target() and instruction.operands[0] == next_next_instruction.operands[0]:
            bytecode_function.ops[i].invert_condition()
            bytecode_function.ops[i].operands = next_instruction.operands
            bytecode_function.ops[i+1] = NopInstruction()
            changed = True
        # SLW [n]:LLW [n] -> DLW [n] and variations
        elif instruction.is_simple_store() and not instruction.has_side_effects() and next_instruction.is_simple_load() and not next_instruction.has_side_effects() and instruction.operands[0] == next_instruction.operands[0] and instruction.data_size() == next_instruction.data_size():
            bytecode_function.ops[i] = Instruction(dup_for_store[instruction.opcode], instruction.operands)
            bytecode_function.ops[i+1] = NopInstruction()
            changed = True
        # LLW [n]:SLW [m]:LLW [n] -> LLW [n]:DLW [m] and variations
        elif instruction.is_simple_load() and instruction == next_next_instruction and next_instruction.is_simple_store() and not instruction.has_side_effects() and not next_instruction.has_side_effects() and not partial_overlap(instruction, next_instruction):
            bytecode_function.ops[i+1] = Instruction(dup_for_store[next_instruction.opcode], next_instruction.operands)
            bytecode_function.ops[i+2] = NopInstruction()
            changed = True
        elif instruction.is_simple_stack_push() and next_instruction.is_a('DROP'):
            bytecode_function.ops[i] = NopInstruction()
            bytecode_function.ops[i+1] = NopInstruction()
            changed = True
        # CN 1:SHL -> DUP:ADD - this is the same length but 9 cycles faster
        # TODO: I haven't actually checked how these two sequences compared for JITted
        # code yet.
        elif instruction.is_constant(1) and next_instruction.is_a('SHL'):
            bytecode_function.ops[i] = Instruction('DUP')
            bytecode_function.ops[i+1] = Instruction('ADD')
            changed = True

        i += 1
    bytecode_function.ops = bytecode_function.ops[:-2] # remove dummy NOPs
    changed = changed or any(op.opcode == NOP_OPCODE for op in bytecode_function.ops)
    bytecode_function.ops = [op for op in bytecode_function.ops if op.opcode != NOP_OPCODE]
    return changed


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
        # SFTODO: DON'T LIKE NEXT TWO LINES RE CLASSIFICATION AND THE 'NOT LB/LW' IS PARTICULARLY UGLY (LOGIC IS PROB CORRECT THO OBSCURED BY THIS)
        is_store = instruction.is_simple_store() or instruction.is_dup_store()
        is_load = (instruction.is_load() and not instruction.is_a('LB', 'LW'))
        if is_store: # stores and duplicate-stores
            # It is possible (if unlikely) a word store will touch a hardware address and
            # a non-hardware address; if this does happen we must never consider it for
            # removal.
            if not instruction.has_side_effects():
                for address in instruction.memory():
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






def get_straightline_blocks(bytecode_function):
    def is_branch_or_target(instruction):
        # SFTODO: THIS MAY NEED TO BE CONFIGURABLE TO DECIDE WHETHER CALL OR ICAL COUNT AS BRANCHES - TBH straightline_optimise() MAY BE BETTER RECAST AS A UTILITY TO BE CALLED BY AN OPTIMISATION FUNCTION NOT SOMETHIG WHICH CALLS OPTIMISATION FUNCTIONS
        return instruction.is_target() or instruction.is_branch()

    foo = FunctionSplitter(bytecode_function)
    for i, instruction in enumerate(bytecode_function.ops):
        if i == 0 or is_branch_or_target(instruction) != is_branch_or_target(bytecode_function.ops[i-1]):
            foo.start_before(i, not is_branch_or_target(instruction))
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

# If the same instruction occurs before all unconditional branches to a target (not
# forgetting the implicit branch to the target if control falls through the target
# from the immediately preceding instruction), and there are no conditional branches
# to the target, the instruction can be moved immediately after the target.
def tail_move(bytecode_function):
    # Dictionary mapping from a target to the possible instruction which can be moved after it.
    candidates = {}
    
    # Set of targets which cannot be modified; these are targets which are:
    # - used by conditional branches
    # - have been demonstrated to have more than one possible instruction which can be
    #   executed immediately before control reaches the target
    unmodifiable_targets = set()

    # Examine all the instructions to populate candidates and unmodified_targets.
    for i, instruction in enumerate(bytecode_function.ops):
        previous_instruction = bytecode_function.ops[i-1] if i>0 else NopInstruction()
        if instruction.is_a('BRNCH') or instruction.is_target():
            if previous_instruction.is_terminator():
                # Nothing to do:
                # - If 'instruction' is BRNCH, it can never be executed (and has
                #   probably already been optimised away) so we don't need to take it
                #   into account.
                # - If 'instruction' is a target, we never fall through it and so
                #   don't need to take its immediate predecessor into account.
                pass
            else:
                # 'previous_instruction' can execute immediately before 'instruction',
                # so record it as a possible candidate for moving. If we've already
                # got a different candidate, we know this target can't be modified.
                target = instruction.operands[0]
                if candidates.setdefault(target, previous_instruction) != previous_instruction:
                    unmodifiable_targets.add(target)
        else:
            # If a target is used in any other instruction, that is a conditional
            # branch of some kind and we know the target cannot be modified.
            instruction.add_targets_used(unmodifiable_targets)

    # Move any candidates which aren't for unmodifiable targets
    changed = False
    new_ops = []
    for instruction in bytecode_function.ops:
        new_ops.append(instruction)
        if instruction.is_a('BRNCH') or instruction.is_target():
            target = instruction.operands[0]
            if target not in unmodifiable_targets:
                candidate = candidates.get(target, None)
                if candidate is not None:
                    assert new_ops[-2] == candidate or new_ops[-2].is_terminator()
                    if new_ops[-2] == candidate:
                        new_ops.pop(-2)
                    if instruction.is_target():
                        new_ops.append(candidate)
                    changed = True
    bytecode_function.ops = new_ops

    return changed

# Used to test for an unlikely case when optimising things like "LLW [n]:SLW [m]:LLW [n]" to
# "LLW [n]:DLW [m]". If m=n this optimisation is valid, but if m=n+1 the final LLW [n] is
# loading a different value than the first and the optimisation cannot be performed.
def partial_overlap(lhs, rhs):
    lhs_memory = lhs.memory()
    rhs_memory = rhs.memory()
    return lhs_memory != rhs_memory and len(lhs_memory.intersection(rhs_memory)) > 0

# If the _INIT function is the trivial default one the PLASMA compiler generates
# automatically, get rid of it; this isn't a huge win but it saves a couple of bytes
# on disk, will have a tiny load-time performance benefit and under certain
# circumstances on the Acorn port it may save a couple of bytes of runtime memory
# (_INIT can't be discarded if it has been trapped below a symbol table chunk).
def optimise_init(module):
    if len(module.bytecode_functions) > 0 and module.bytecode_functions[-1].is_init():
        init = module.bytecode_functions[-1].ops
        trivial_init = [Instruction(CONSTANT_OPCODE, [0]),
                        Instruction('RET')]
        if init == trivial_init:
            module.bytecode_functions.pop(-1)

def optimise(module):
    for bytecode_function in module.bytecode_functions:
        # SFTODO: The order here has not been thought through at all carefully and may be sub-optimal
        changed = True
        while changed:
            changed1 = True
            while changed1:
                # SFTODO: This seems a clunky way to handle 'changed' but I don't want
                # short-circuit evaluation. I think we can do 'changed = function() or changed', if
                # we want...
                result = []
                if True: # SFTODO TEMP
                    result.append(target_deduplicate(bytecode_function))
                    #assert result[-1] or (SFTODO == bytecode_function.ops)
                    result.append(branch_optimise(bytecode_function))
                    result.append(branch_optimise2(bytecode_function))
                    result.append(branch_optimise3(bytecode_function))
                    result.append(remove_orphaned_targets(bytecode_function))
                    result.append(remove_dead_code(bytecode_function))
                    result.append(move_case_blocks(bytecode_function))
                    result.append(peephole_optimise(bytecode_function))
                    result.append(straightline_optimise(bytecode_function, [optimise_load_store]))
                    #if SFTODOFOO:
                    #    break
                changed1 = any(result)
            #remove_dead_code(bytecode_function) # SFTODO
            changed2 = True
            # We do these following optimisations only when the ones above fail to produce any
            # effect. These can reorder code but this can give (slightly) unhelpful/confusing
            # re-orderings, so we let the more localised optimisations above have first go.
            # SFTODO: It may be worth putting all this back into a single loop later on to see if
            # this is actually still true.
            while changed2:
                result = []
                result.append(block_deduplicate(bytecode_function))
                result.append(block_move(bytecode_function))
                result.append(tail_move(bytecode_function))
                changed2 = any(result)
            changed = changed1 or changed2

    optimise_init(module)

    # In order to remove unused objects from the module, we determine the set of
    # dependencies (data/asm LabelledBlob and BytecodeFunctions), starting with _INIT
    # (if present)
    # and any exported symbols and recursively adding their dependencies. If the
    # data/asm blob is present but unused (unlikely) we will (correctly) remove it,
    # but the main reason for doing this is to remove unused bytecode functions. We do
    # this after optimising the code to take advantage of any dead code removal.
    dependencies = set()
    if len(module.bytecode_functions) > 0 and module.bytecode_functions[-1].is_init():
        module.bytecode_functions[-1].add_dependencies(dependencies)
    for external_name, reference in module.esd.entry_dict.items():
        reference.add_dependencies(dependencies)
    # dependencies now contains only objects which are needed. We preserve the
    # order of things in the input module; this automatically ensure that the
    # data/asm blob comes first and _INIT comes last, and it also avoids gratuitous
    # reordering which makes comparing the input and output difficult.
    dependencies_ordered = [module.data_asm_blob] + module.bytecode_functions
    dependencies_ordered = [x for x in dependencies_ordered if x in dependencies]
    if module.data_asm_blob not in dependencies_ordered:
        module.data_asm_blob = None
    else:
        assert dependencies_ordered[0] == module.data_asm_blob
        dependencies_ordered.pop(0)
    module.bytecode_functions = dependencies_ordered





# TODO: Perhaps not worth it, and this is a space-not-speed optimisation, but if it's common to CALL a function FOO and then immediately do a DROP afterwards (across all code in the module, not just one function), it may be a space-saving win to generate a function FOO-PRIME which does "(no ENTER):CALL FOO:DROP:RET" and replace CALL FOO:DROP with CALL FOO-PRIME. We could potentially generalise this (we couldn't do it over multiple passes) to recognising the longest common sequence of operations occurring after all CALLs to FOO and factoring them all into FOO-PRIME.

# TODO: It would seem a good idea to do an initial pass expanding DUP where the preceding instruction is something "simple" like LLW [n], because my simplistic optimisation code will tend to be thrown by the presence of a DUP. We could then do a final DUPification pass (or perhaps include this in the optimisation loop, but only once we run out of other changes to make) to re-introduce DUP in cases like the ones we expanded. I haven't done this yet because some experiments and manual examination of the self-hosted compiler suggest that this would have no benefit for it, and it is my main test case at the moment.
# TODO: On a similar theme, perhaps we should initially expand DROP2->DROP:DROP and do a "final" DROP:DROP->DROP2 to reverse this.

# TODO: The peephole optimiser can do things like "LLW [n]:SLW [m]:LLW [n] -> LLW [n]:DLW
# [m]", but we could also do things like "LLW [n]:DLW [m]:SLW [o]:LLW [n] -> LLW
# [m]:DLW [m]:DLW [o]". An arbitrary number of dup-stores after the first LLW would be
# acceptable, not just one; the current peephole optimiser will not do anything if there
# are any dup-stores after the first load instruction.
