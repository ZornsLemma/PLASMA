# https://stackoverflow.com/questions/32030412/twos-complement-sign-extension-python
def sign_extend(value, bits=16):
    sign_bit = 1 << (bits - 1)
    return (value & (sign_bit - 1)) - (value & sign_bit)


class ComparisonMixin(object):
    """Mixin class which uses a keys() method to implement __eq__(), __ne__() and __hash__()"""

    def __eq__(self, other):
        if type(self) == type(other):
            return self.keys() == other.keys()
        return False

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash(self.keys())
