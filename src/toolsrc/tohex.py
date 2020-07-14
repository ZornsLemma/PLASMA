import sys

with open(sys.argv[1], 'rb') as f:
    s = ''
    while True:
        c = f.read(1)
        if len(c) == 0:
            break
        if c == '\n':
            s += '\\n' # note this is a different binary character, this won't always be appropriate
            print '"%s"' % s
            s = ''
        elif 32 <= ord(c) <= 126:
            s += c
        else:
            s += '\\$' + ('00' + hex(ord(c)))[-2:]
if s != '':
    print '"%s"' % s
