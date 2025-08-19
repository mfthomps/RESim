#!/usr/bin/env python3
'''
Collect new words from level directories
'''
import sys
import os
import pickle
def collectWords(in_dir, word_list):
    word_file = os.path.join(in_dir,'word_list.pkl')
    if os.path.isfile(word_file):
        with open(word_file, 'rb') as fh:
            these_words = pickle.load(fh)
            for some_list in these_words:
                for word in some_list:
                    #word = some_list[1]
                    if word not in word_list:
                        print(word)
                        word_list.append(word)
            next_dir = os.path.join(in_dir, 'next_level')
            if os.path.isdir(next_dir):
                dir_list = os.listdir(next_dir)
                for d in dir_list:
                    dpath = os.path.join(next_dir, d)
                    if os.path.isdir(dpath):
                        collectWords(dpath,word_list)
            else:
                #print('Nothing at %s, done' % next_dir)
                pass
in_dir = sys.argv[1]
word_list = []
collectWords(in_dir, word_list)
with open('/tmp/word.list', 'w') as fh:
    for word in word_list:
       wordd = word.decode()
       fh.write(wordd+'\n')
