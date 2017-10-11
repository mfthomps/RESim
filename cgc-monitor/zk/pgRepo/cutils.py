import os
mit_top = '/mnt/data'
def getCSID(cset):
    num_bins = len(cset.cbs)
    csid = 'CB%s%02d' % (cset.name, num_bins)
    return csid

def safeMkDir(path):
    try:
        os.makedirs(path)
    except OSError as e:
        if e.errno != 17:
            print('error in safeMkDir %s' % e)
            exit(1) 
       
