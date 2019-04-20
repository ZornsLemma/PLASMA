from __future__ import print_function

import struct

from operands import *
from bytecode import *

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






