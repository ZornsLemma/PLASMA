from __future__ import print_function
import sys
import io

# TODO: Shouldn't assert for user errors...

assert len(sys.argv) == 3

master = io.open(sys.argv[1], 'rb').read()
alternate = io.open(sys.argv[2], 'rb').read()
assert len(master) == len(alternate)
assert bytes(master[-2:]) == b'\x00\x00'

delta = 1000
relocations = []
# TODO: Yay, Python 2 and 3 incompatibilities. Is there a better way?
python_2 = (type(master[0]) is str)
for i in range(len(master)):
    if master[i] != alternate[i]:
        relocations.append(i)
        if python_2:
            this_delta = ord(alternate[i]) - ord(master[i])
        else:
            this_delta = alternate[i] - master[i]
        if delta == 1000:
            delta = this_delta
        else:
            assert delta == this_delta

assert len(relocations) > 0
assert relocations[0] != 0 # we can't encode this
delta_relocations = []
last_relocation = 0
for relocation in relocations:
    delta_relocation = relocation - last_relocation
    last_relocation = relocation
    assert delta_relocation > 0
    # We need to encode the delta_relocation as an 8-bit byte. We use 0 to mean
    # 'move 256 bytes along but don't perform a relocation'.
    while delta_relocation >= 256:
        delta_relocations.append(0)
        delta_relocation -= 256
    delta_relocations.append(delta_relocation)

count = len(delta_relocations)
delta_relocations[:0] = [count & 0xff, count >> 8]

with open(sys.argv[1], 'wb') as f:
    f.write(master[:-2])
    f.write(bytearray(delta_relocations))
