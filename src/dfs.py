# This module is based on Richard Cook's 'ssdtools':
# https://github.com/rcook/ssdtools
#
# Copyright (c) 2015 Richard Cook
# Copyright (c) 2017 Steven Flintham
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.



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

    def __str__(self):
        return self.name



class Image:
    def __init__(self):
        self.files = {}
        self.title = ''
        self.boot_option = 0 # TODO: use an enum?
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
	class Catalogue:
            pass

        # https://stackoverflow.com/questions/14822184/is-there-a-ceiling-equivalent-of-operator-in-python
        def ceildiv(a, b):
            return -(-a // b)

        SECTOR_BYTE_COUNT = 256
        FILE_NAME_LENGTH = 7

        class FileDescriptor:
            def __init__(self, file_name, load_address, execution_address, data):
                self.dir = str(k)[0]
                self.file_name = str(k)[2:]
                self.load_address = load_address
                self.execution_address = execution_address
                self.data = data
                self.sector_count = ceildiv(len(data), SECTOR_BYTE_COUNT)

        catalogue = Catalogue()
        catalogue.disc_title = self.title[:12]
        catalogue.boot_option = self.boot_option
        catalogue.file_descriptors = [FileDescriptor(k, v[0], v[1], v[3]) for k, v in self.files.items()]
        catalogue.sector_count = 80 * 10

        sector = 2
        for file_descriptor in catalogue.file_descriptors:
            file_descriptor.start_sector = sector
            sector += file_descriptor.sector_count
            # TODO: Something - ideally add_file() - should be responsible for checking we don't overfill the disc

	sector0_data = bytearray(8) + bytearray([32] * (SECTOR_BYTE_COUNT - 8))
	sector1_data = bytearray(SECTOR_BYTE_COUNT)

	for i in range(len(catalogue.disc_title)):
	  if i < 8:
	    sector0_data[i] = catalogue.disc_title[i]
	  else:
	    sector1_data[i - 8] = catalogue.disc_title[i]

	sector1_data[4] = 0 # cycle number
	sector1_data[5] = len(catalogue.file_descriptors) * 8
	sector1_data[6] = \
	  ((catalogue.boot_option << 4) | \
	  ((catalogue.sector_count >> 8) & 0b00000011))
	sector1_data[7] = catalogue.sector_count & 0b11111111

	next_sector = 2
	for i, file_descriptor in enumerate(catalogue.file_descriptors):
	  start_index = (i + 1) * 8

	  for j in range(0, len(file_descriptor.file_name)):
	    sector0_data[start_index + j] = file_descriptor.file_name[j]
	  sector0_data[start_index + FILE_NAME_LENGTH] = file_descriptor.dir

	  sector1_data[start_index + 0] = (file_descriptor.load_address >> 0) & 0b11111111
	  sector1_data[start_index + 1] = (file_descriptor.load_address >> 8) & 0b11111111
	  sector1_data[start_index + 2] = (file_descriptor.execution_address >> 0) & 0b11111111
	  sector1_data[start_index + 3] = (file_descriptor.execution_address >> 8) & 0b11111111
	  sector1_data[start_index + 4] = (len(file_descriptor.data) >> 0) & 0b11111111
	  sector1_data[start_index + 5] = (len(file_descriptor.data) >> 8) & 0b11111111
	  sector1_data[start_index + 6] = \
	    (((file_descriptor.start_sector >> 8) & 0b11) << 0) | \
	    (((file_descriptor.load_address >> 16) & 0b11) << 2) | \
	    (((file_descriptor.execution_address >> 16) & 0b11) << 6) | \
	    (((len(file_descriptor.data) >> 16) & 0b11) << 4)
	  sector1_data[start_index + 7] = file_descriptor.start_sector & 0b11111111

	sectors = []
	sectors.append(sector0_data)
	sectors.append(sector1_data)

        image = sector0_data
        image += sector1_data
	for file_descriptor in catalogue.file_descriptors:
	  assert len(sectors) == file_descriptor.start_sector
	  for i in range(file_descriptor.sector_count):
	    file_data = file_descriptor.data[i * SECTOR_BYTE_COUNT : (i + 1) * SECTOR_BYTE_COUNT]
	    image += file_data + bytearray(SECTOR_BYTE_COUNT - len(file_data))

        return image


d = Image()
d.set_title('Test disc')
d.add_file('foo', bytearray('Hello world\r'))
with open('foo.ssd', 'wb') as f:
    f.write(d.get())
