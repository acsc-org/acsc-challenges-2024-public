#!/usr/bin/env python3

import argparse

def main():
    # get argument from command line
    parser = argparse.ArgumentParser()
    # define argument (address)
    parser.add_argument('address', type=lambda x: int(x, base=0), help='Address to replace')
    # get arg
    args = parser.parse_args()
    
    # get data from EncryptFlag
    d = bytearray(open('PrintFlagOriginal', 'rb').read())
    d[args.address:args.address+16] = bytearray(b'CanYouFindTheKey')

    open('PrintFlag', 'wb').write(d)

if __name__ == '__main__':
    main()
