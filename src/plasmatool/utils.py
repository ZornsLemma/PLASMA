# https://stackoverflow.com/questions/32030412/twos-complement-sign-extension-python
def sign_extend(value, bits=16):
    sign_bit = 1 << (bits - 1)
    return (value & (sign_bit - 1)) - (value & sign_bit)
