#!/usr/bin/env python3
'''
'''
import sys
import os
import zlib
def cksum(file_path):
    crc = 0
    try:
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(4096)  # Read in chunks for efficiency
                if not chunk:
                    break
                crc = zlib.crc32(chunk, crc)

        crc = crc & 0xFFFFFFFF  # Ensure 32-bit unsigned integer

        return crc

    except FileNotFoundError:
        print(f"Error: File not found at {file_path}")
        return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def checkThis(in_dir, cksum_dict, stop_dir=None):
    queue_dir = os.path.join(in_dir, 'queue')
    if os.path.isdir(queue_dir):
        flist = os.listdir(queue_dir)
        print('Summing hits in files in %s' % queue_dir)
        for f in flist:
            fpath = os.path.join(queue_dir, f)
            crc = cksum(fpath)
            #print('0x%x %d %s' % (crc, size, fpath))    
            if crc not in cksum_dict:
                cksum_dict[crc] = fpath
            else:
                print('CRC for %s already exists for %s' % (fpath, cksum_dict[crc]))
        next_dir = os.path.join(in_dir, 'next_level')
        if os.path.isdir(next_dir) and (stop_dir is None or stop_dir != next_dir):
            dir_list = os.listdir(next_dir)
            for d in dir_list:
                dpath = os.path.join(next_dir, d)
                if os.path.isdir(dpath):
                    checkThis(dpath, cksum_dict)
        else:
            print('Nothing at %s, done' % next_dir)
    else:
        print('no queue dir at %s' % queue_dir)

def main():
    cksum_dict = {}
    in_dir = sys.argv[1]
    checkThis(in_dir, cksum_dict)

if __name__ == '__main__':
    sys.exit(main())

