import functools



@functools.total_ordering
class Filename:
    def __init__(self, name):
        assert Filename.valid_name(name)
        if '.' not in name:
            name = '$.'+name
            assert Filename.valid_name(name)
        self.name = name

    @staticmethod
    def valid_name(name):
        return True # TODO!

    def _is_valid_operand(self, other):
        return isinstance(self, Filename) and isinstance(other, Filename)

    def __hash__(self):
        return hash(self.name.lower())

    def __eq__(self, other):
        if not self._is_valid_operand(other):
            return NotImplemented
        return self.name.lower() == other.name.lower()

    def __lt__(self, other):
        if not self._is_valid_operand(other):
            return NotImplemented
        return self.name.lower() < other.name.lower()

    def __str(self):
        return self.name



class Image:
    def __init__(self):
        self.files = {}
        self.title = ''
        # TODO: Might be nice to have some way for caller to specify a file
        # ordering, so that on a physical disc the files can be arranged in
        # logical order to minimise seeks. A bit OTT really.

    def add_file(self, filename, data, load_addr=0x00000000, exec_addr=0x00000000, locked=False):
        if not isinstance(filename, Filename):
            filename = Filename(filename)
        assert len(self.files) < 31
        self.files[filename] = [load_addr, exec_addr, locked, data]

    def set_title(self, title):
        # TODO: validate
        self.title = title

    def get(self):
        sector0 = bytearray(256)
        sector1 = bytearray(256)

        padded_title = (bytearray(self.title, 'ascii') + bytearray(' ', 'ascii')*12)[:12]
        sector0[0:8] = padded_title[:8]
        sector1[0:4] = padded_title[9:]

        for i, name in enumerate(self.files):
            directory = bytearray([str(name)[0]])
            print(repr(directory))
            filename = (bytearray(str(name)[2:]) + bytearray(' ', 'ascii')*7)[:7]
            offset = 8 + i*8
            sector0[offset:offset+7] = filename
            sector0[offset+8] = directory[0]


d = Image()
d.set_title('Test disc')
d.add_file('foo', bytearray('Hello world\r'))
with open('foo.ssd', 'wb') as f:
    f.write(d.get())
