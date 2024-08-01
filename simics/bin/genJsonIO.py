#!/usr/bin/env python3
import sys
import json
import binascii
import argparse

def doJson(args):
    if args.output:
        outfile = args.output
    else:
        outfile = '/tmp/io.json'
    flist = []
    for f in args.namelist:
        flist.append(f)
    pack_list = []
    for f in flist:
        with open(f, 'rb') as fh:
            packet = fh.read()
            #pack_list.append(bytes.decode(packet, encoding='unicode-escape'))
            pack_list.append(str(binascii.hexlify(packet)))

    if args.host is None:
        # JSON will only contain data, e.g., for use by drive driver
        jout = json.dumps(pack_list)
        with open(outfile, 'w') as fh:
            fh.write(jout)
        print('Wrote %d files to %s\n' % (len(pack_list), outfile))
    else:
        jdict = {}
        jdict['host'] = args.host
        jdict['port'] = int(args.port)
        jdict['hang'] = args.hang
        jdict['data'] = pack_list
        jout = json.dumps(jdict)
        with open(outfile, 'w') as fh:
            fh.write(jout)
        print('Wrote json to %s for use by injectIO.\n' % (outfile))


def main():
    parser = argparse.ArgumentParser(prog='genJsonIO.py', description='Generate a json file from a given set of input files.  Intended for use with drive-driver to send multiple UDP packets or a TCP stream from the driver to the target.  And more importantly, these files can be provided to injectIO when the prep inject snapshot is of the driver.  If drive-driver is to be used, do not include host, port or hang, which should be expressed in the directive file.  These values should be provided to create a JSON for use with injectIO.')
    parser.add_argument('-n', '--namelist', nargs='+', default=[], action='store', help='List of input files names.')
    parser.add_argument('-o', '--output', action='store', help='Name of output file.')
    parser.add_argument('-i', '--host', action='store', help='IP of host.')
    parser.add_argument('-p', '--port', action='store', help='TCP Port.')
    parser.add_argument('-g', '--hang', action='store_true', help='Leave connection open.')
    args = parser.parse_args()
    doJson(args)

if __name__ == '__main__':
    sys.exit(main())
