#!/usr/bin/env python2

import re
import sys
import random

ALPHABET = '0123456789abcdef'

def random_mac(m):
    return ':'.join(random.choice(ALPHABET) + random.choice(ALPHABET) for _ in range(6))

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print "Usage: {} <policy>".format(sys.argv[0])
        sys.exit(1)

    mac = re.compile('([a-fA-F0-9X]{2}\:){5}[a-fA-F0-9X]{2}')
    with open(sys.argv[1], 'r') as f:
        contents = f.read()
    nf = mac.sub(random_mac, contents) 
    print nf
