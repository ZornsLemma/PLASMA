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

# bidict taken from Basj's answer at https://stackoverflow.com/questions/3318625/efficient-bidirectional-hash-table-in-python
class bidict(dict):
    def __init__(self, *args, **kwargs):
        super(bidict, self).__init__(*args, **kwargs)
        self.inverse = {}
        for key, value in self.iteritems():
            self.inverse.setdefault(value,[]).append(key) 

    def __setitem__(self, key, value):
        if key in self:
            self.inverse[self[key]].remove(key) 
        super(bidict, self).__setitem__(key, value)
        self.inverse.setdefault(value,[]).append(key)        

    def __delitem__(self, key):
        self.inverse.setdefault(self[key],[]).remove(key)
        if self[key] in self.inverse and not self.inverse[self[key]]: 
            del self.inverse[self[key]]
        super(bidict, self).__delitem__(key)

