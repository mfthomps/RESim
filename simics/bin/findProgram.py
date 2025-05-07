#!/usr/bin/env python3
import sys
import os
import os
import json
import argparse

def main():
    parser = argparse.ArgumentParser(prog='findProg', description='Find path to a program.')
    parser.add_argument('prog', action='store', help='The target program')
    args = parser.parse_args()
    here = os.getcwd()
    image_dir = os.getenv('RESIM_IMAGE')
    if image_dir is None:
        print('RESIM_IMAGE not defined')
        exit(1)
    remain = here[len(image_dir)+1:] 
    resim_analysis = os.getenv('IDA_ANALYSIS')
    if resim_analysis is None:
        print('IDA_ANALYSIS not defined')
        exit(1)
    analysis = os.path.join(resim_analysis, remain)
    #print('analysis is %s' % analysis)
    exec_json_path = os.path.join(analysis, 'exec_dict.json')
    if os.path.isfile(exec_json_path):
        with open(exec_json_path) as fh:
            exec_dict = json.load(fh)
            if args.prog in exec_dict:
                print('%s' % exec_dict[args.prog]['path'])
    else: 
        sys.stderr.write('No exec_list.json found at %s\n' % exec_json_path)
        exit(1)
            
if __name__ == '__main__':
    sys.exit(main())

