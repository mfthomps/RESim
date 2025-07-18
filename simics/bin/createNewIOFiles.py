#!/usr/bin/env python3
import sys
import re
import json
import os
import pickle
import argparse

word_list = []
outputdir = os.path.join(os.getcwd(),"new_iofiles")

def create_new_iofiles(seedfile, watchmarkfile, add_count=0):
    '''
    Create new input files based on strcmp in watchmark file or in trackio files.
    If there's a strcmp, replace the input string with the expected string
    Check for duplicates
    '''
    with open(watchmarkfile, 'r') as infile:
        # Check if it's JSON, otherwise treat as text file
        try:
            data=json.load(infile)
            inword_list, newword_list = [],[]
            find_json_field(data, 'src_str', inword_list) 
            find_json_field(data, 'dst_str', newword_list)    
        
        except json.JSONDecodeError:
            infile.seek(0)
            inword_list, newword_list = get_words(infile) 

    # Check and fix if the comparison is between new word and orig word, instead of orig word and new word
    inword_list, newword_list = check_comparison(inword_list,newword_list, seedfile)
    
    # Check if there are duplicates and remove from list
    inword_list, newword_list = check_duplicates(inword_list, newword_list)
    
    # Create new seed file with replaced string
    try:
        os.mkdir(outputdir)
    except:
        pass
    for i in range(len(newword_list)-1): 
        create_file(i, seedfile, inword_list[i], newword_list[i], add_count)
    
    infile.close()

def check_duplicates(inlist,newlist):
    '''
    Check if the original word and the new word have already been processed, or if the two words are the same. 
    Add every new word pair to word_list.
    '''
    updated_inwordlist, updated_newwordlist = [],[]
    for i in zip(inlist, newlist):
        if list(i) in word_list:
            continue
        if i[0]==i[1]:
            continue
        else:
            word_list.append(list(i)) 
            updated_inwordlist.append(i[0])
            updated_newwordlist.append(i[1])
    return updated_inwordlist, updated_newwordlist

def find_json_field(data, field_name, results):
    """
    Recursively search for string in a JSON file.
    """
    if isinstance(data, dict):
        for key, value in data.items():
            if key == field_name:
                results.append(value.encode('utf-8'))
            else:
                find_json_field(value, field_name, results)  # Recursively search in the value
    elif isinstance(data, list):  # If it's a list
        for item in data:
            find_json_field(item, field_name, results)  # Recursively search each item

def isStrCmp(line):
    if 'strcmp' in line or 'strncmp' in line or 'strcasecmp' in line or 'strncasecmp' in line:
        return True
    else:
        return False

def get_words(infile):
    '''
    Go through infile line by line and look for strcmp. Add the comparison words to new_wordlist and inword_list.
    '''
    inword_list = []
    newword_list = [] 
    for line in infile:
        if isStrCmp(line):
            space_split = line.split(' ')
            # Input string is after third space
            inword = space_split[3]
            # Expected string comes after ' to '
            to_split = line.split(' to ')
            newword = to_split[1].split(' ')[0]
            inword_list.append(inword.encode('utf-8'))
            newword_list.append(newword.encode('utf-8'))                 
        else:
            continue
    return inword_list, newword_list
    
def check_comparison(inwordlist,newwordlist, seedfile):
    ''' 
    Open original iofile to check if the comparison is xy or yx 
    '''
    updated_inwordlist, updated_newwordlist = [],[]
    check_seedf1 =  open(seedfile, 'rb')
    seed_content = check_seedf1.read()
    for i in range(len(inwordlist)):
        inword = inwordlist[i]
        newword = newwordlist[i]
        if inword.lower() not in seed_content.lower() and newword.lower() in seed_content.lower():
            inword, newword = newword, inword
        updated_inwordlist.append(inword)
        updated_newwordlist.append(newword)
    check_seedf1.close()
    return updated_inwordlist, updated_newwordlist

def create_file(j, seedfile, inword, newword, add_count=1):
    '''
    Create new file based on original iofile. Substitute inword with newword.
    '''
    # Create new seedfile
    outfile_name = f"{outputdir}/track{add_count}_seedfile{j}.io"    
    # Counter to check if an original word isn't found in the seedfile 
    i=0
    with open(outfile_name, 'wb') as outputfile:
        seedf =  open(seedfile, 'rb')
        for line in seedf:
            newline = re.sub(re.escape(inword), newword, line, flags=re.IGNORECASE)
            outputfile.write(newline)
            if newline!= line:
                i+=1
        seedf.close()
    outputfile.close()
    if i==0:
        # Write exception to file:
        with open('exception_file.txt', 'ab') as errorfile:
            errorfile.write((b"Found a strcmp, but original word not found in io file.\n"))
            errorfile.write(b"Original word: " + inword + b"\n")
            errorfile.write(b"New word: " + newword + b"\n")
            errorfile.write(b"---------\n")
        # Delete file
        os.remove(outfile_name)

def multiple_watchmarkfiles(inputdir, iofile):
    here = os.getcwd()
    file_list=[]
    file_path = os.path.join(here,inputdir)
    track_list = os.listdir(file_path)
    for track in track_list:
        file_list.append(os.path.join(file_path,track))

    add_count = 0
    for track in file_list:
        create_new_iofiles(iofile, track, str(add_count))
        add_count+=1

def get_wordlist():
    output_file = "word_list.pkl"
    if os.path.exists(output_file):
        # Import the list from the JSON file
        try:
            with open(output_file, 'rb') as f:
                word_list = pickle.load(f)
        except Exception as e:
            print(f"An error occurred trying to open the word list: {e}")
    else:
        return

def save_wordlist():
    # Save the list to a JSON file
    output_file = "word_list.pkl"
    try:
        with open(output_file, 'wb') as f:
            pickle.dump(word_list, f)
    except Exception as e:
        print(f"An error occurred trying to save the word list: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='createNewIOFiles.py', description='Generate new IO files, e.g., for seeds, based on string compares found in watch marks.')
    parser.add_argument('iofile', action='store', help='The original io file that generated the watch marks')
    parser.add_argument('watchmarks', action='store', help='Either a single watch mark file, or the directory to one created from fuzzing output')
    args = parser.parse_args()
    
    # Import word_list if it exists
    get_wordlist()
        
    if os.path.isdir(args.watchmarks):
        multiple_watchmarkfiles(args.watchmarks,args.iofile)            
    elif os.path.isfile(args.watchmarks):
        create_new_iofiles(args.iofile, args.watchmarks)
    else:
        print(f"'{args.watchmarks}' does not exist.")
        sys.exit()
    #Save word_list to file
    save_wordlist()
        
    print("New files in dir '/new_iofiles'")
    print("Potential errors in exception_file.txt.")    
    print("List of new substitutions saved in word_list.pkl.")
