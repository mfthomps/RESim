#!/usr/bin/env python3
import sys
import json
import binascii
import argparse

def tokenCookie(item):
    cookie = None
    new_item = item
    for line in item.splitlines():
        if line.startswith(b'Cookie:'):
            parts = line.split(b'=')
            cookie = parts[1].strip()
            #print('cookie is %s' % cookie)
            break
    return cookie
    

def doWeb(packet, pack_list, replace_cookie):
    delim = b"RESIM_WEB_DELIM"
    parts = packet.split(delim)
    cookie = None
    for item in parts:
        if replace_cookie:
            # always do a replace once we find any cookie 
            # so that we hit cookies in jsons and such
            new_cookie = tokenCookie(item)
            if new_cookie is not None:
                cookie = new_cookie 
            if cookie is not None:
                item = item.replace(cookie, b'RESIM_COOKIE')
        pack_list.append(binascii.hexlify(item).decode())

    print('num parts is %d' % len(parts))


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
            if args.web:
                doWeb(packet, pack_list, args.cookie)
            else:
                #pack_list.append(bytes.decode(packet, encoding='unicode-escape'))
                the_bytes = binascii.hexlify(packet)
                pack_part = the_bytes.decode()
                pack_list.append(pack_part)

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
    parser = argparse.ArgumentParser(prog='genJsonIO.py', description='Generate a json file from a given set of input files.  Intended for use with drive-driver to send multiple UDP packets or a TCP stream from the driver to the target.  Also, the output can be provided to injectIO when the prep inject snapshot is of the driver.  If the host option is provided, the host/port/hang will override values in the directive file.  These option values must be provided when creating a JSON for use with injectIO.')
    parser.add_argument('-n', '--namelist', nargs='+', default=[], action='store', help='List of input files names.')
    parser.add_argument('-o', '--output', action='store', help='Name of output file.')
    parser.add_argument('-i', '--host', action='store', help='IP of host.')
    parser.add_argument('-p', '--port', action='store', help='TCP Port.')
    parser.add_argument('-g', '--hang', action='store_true', help='Leave connection open.')
    parser.add_argument('-w', '--web', action='store_true', help='Parse each input file for RESIM_WEB_DELIM sequences and break those into individual json entries, intended for consuming data captured from web sessions.')
    parser.add_argument('-c', '--cookie', action='store_true', help='uh.')
    args = parser.parse_args()
    doJson(args)

if __name__ == '__main__':
    sys.exit(main())
