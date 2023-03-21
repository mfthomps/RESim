import pickle
import resimUtils
'''
Routines to tease out Windows 7 kernel parameters for use by RESim
Assumes a task_list.pickle file was created identifying addresses of
some set of task records, obtained by watching the current task
pointer. Note this list was dynamically created and will not necessarily
match the single state of the current machine, e.g., tasks may have been
created and deleted.
'''
def findRecordSize(cpu, mem_utils, task_list):
    #task_list = pickle.load(open('task_list.pickle', 'rb'))
    first_task = 0xffffffffffffffff
    record_size = 0xffffffffff
    retval = []
    for task in task_list:
        if task < first_task:
            first_task = task
        least = 0xfffffffffffff
        #print('task 0x%x' % task)
        for other in task_list:
            if other == task:
                continue
            delta = abs(other - task)
            if delta < least:
                least = delta
        #print('least is 0x%x' % least)
        if least not in retval:
            retval.append(least)
    #print('first_task 0x%x size 0x%x' % (first_task, record_size))
    return first_task, sorted(retval)

def showRecordStarts(cpu, mem_utils, orig_task_list):
    #orig_task_list = pickle.load(open('task_list.pickle', 'rb'))
    task_list = sorted(orig_task_list)[3:150]
    prev = None
    delta = 0
    for task in task_list:
        if prev is not None:
            delta = task - prev
        print('task: 0x%x dalte 0x%x' % (task, delta))
        prev = task

def findAdjacentRecords(cpu, mem_utils, record_size, orig_task_list):
    #orig_task_list = pickle.load(open('task_list.pickle', 'rb'))
    task_list = sorted(orig_task_list)[3:150]
    task1 = []
    task2 = []

    prev = None
    delta = 0
    for task in task_list:
        if prev is not None:
            delta = task - prev
            if delta == record_size:
                task1.append(prev)
                task2.append(task)
                #print('task: 0x%x dalta 0x%x' % (task, delta))
        prev = task
    return task1, task2    

def unused(cpu, mem_utils):
    words = {}
    dup_words = []
    orig_task_list = pickle.load(open('task_list.pickle', 'rb'))
    task_list = sorted(orig_task_list)[3:50]
    delta = 0
    prev = None
    num_words = 158
    for i in range(num_words):
        words[i] = []
    for task in sorted(task_list):
        cur = task
        for i in range(num_words):
            if i in dup_words: 
                continue
            val = mem_utils.readWord(cpu, cur)
            if val not in words[i]:
                words[i].append(val)
            elif val != 0:
                print('entry %d val 0x%x already found, bail' % (i, val))
                dup_words.append(i) 
            cur = cur + 8
    for i in range(num_words):
        if i in dup_words:
            continue
        for val in words[i]:
            print('unique at %d 0x%x' % (i, val))

def walkList(cpu, mem_utils, task, offsets, orig_task_list):
    '''
    Given a task address and a list of offsets to what we think are HEAD link lists,
    walk each task list and record and return the tasks.

    '''
    #orig_task_list = pickle.load(open('task_list.pickle', 'rb'))
    task_list = sorted(orig_task_list, reverse=True)

    record_count = {}
    task_matches = {}
    got_tasks = {}
    for head_off in offsets:
        #print('HEAD offset %d 0x%x' % (head_off, head_off))
        task_ptr = task
        match_count = 0
        next_head = task_ptr + head_off
        got = []
        for i in range(1000):
            task_next = next_head+8
            val = mem_utils.readWord(cpu, task_next)
            if val is None:
                #print('died on task_next 0x%x' % task_next)
                break
            else:
                next_head = val
            
            next_ptr = next_head - head_off
            task_ptr = next_head - head_off
            #for task in task_list:
            #    if task < task_ptr:
            #        print('delta %d' % ((task_ptr - task)))
            #        break


            if task_ptr in task_list:
                match_count += 1
            if task_ptr in got:
                #print('already got')
                break
            else:
                got.append(task_ptr)
        if match_count > 1 and len(got) > 5:
            print('walkList task 0x%x offset %d walked(got) %d records, with %d matches in task_list' % (task, head_off, len(got), match_count))
            record_count[head_off] = len(got)
            task_matches[head_off] = match_count
            got_tasks[head_off] = got
    return record_count, task_matches, got_tasks


def findHeads(cpu, mem_utils, task1, task2):
    ''' Given the address of what looks like 2 adjacent task records,
        look for pointers in task1 that point to addresses within task2
    '''
    
    #task1 = 0xfffffa8007096640 
    #task2 = 0xfffffa8007096b50 
    ''' observed size of records, make it a parameter'''
    num_words = 158
    t1offset = 8 
    cur = task1 + t1offset
    retval = []
    delta = task2-task1
    print('findHeads for adjacent tasks 0x%x and 0x%x, delta %d 0x%x' % (task1, task2, delta, delta))
    while cur < task2:
        val = mem_utils.readWord(cpu, cur)
        if val >= task2 and val <= (task2+num_words*8):
            ''' think val is pointing to a HEAD struct '''
            head_offset = t1offset - 8
            print('findHeads read from 0x%x (%d bytes from task1 0x%x) value 0x%x' % (cur, t1offset, task1, val))
            task2_guess = val - head_offset
            if task2_guess == task2:
                print('\tguess matches task2, single pointer?')
                retval.append(head_offset)
            else:
                print('\tguess is %d bytes short' % ((task2-task2_guess)))

            #t2offset = val - task2 
            #print('\ttask1 offset %d val 0x%x points into task2 offset %d' % (t1offset, val, t2offset)) 
            #val2 = mem_utils.readWord(cpu, val)
            #print('\ttask2 points to 0x%x ' % val2)
            #val3 = mem_utils.readWord(cpu, (val+8))
            #print('\ttask2 next? points to 0x%x ' % val3)
        t1offset = t1offset+8 
        cur = task1 + t1offset
    return retval
  
def findUnique(cpu, mem_utils, offset, task_list): 
    #task_list = pickle.load(open('head-768.pickle', 'rb'))
    #pfile = 'head-%d.pickle' % offset
    #print('Unique for offset %d' % offset)
    #task_list = pickle.load(open(pfile, 'rb'))
    words = {}
    dup_words = []
    delta = 0
    prev = None
    num_words = 158
    retval = []
    for i in range(num_words):
        words[i] = []


    look_for = offset + 8

    for task in task_list:
        #print('task 0x%x' % cur)
        for i in range(num_words):
            if i in dup_words: 
                continue
            off = i*8
            cur = task + off
            val = mem_utils.readWord(cpu, cur)
            if val not in words[i]:
                words[i].append(val)
            elif val != 0:
                if i not in dup_words:
                    dup_words.append(i) 
    

    for i in range(num_words):
        if i in dup_words:
            continue
        offset = i*8
        zero_count = 0
        for task in task_list:
            ptr = task+offset
            val = mem_utils.readWord(cpu, ptr)
            if val == 0:
                zero_count += 1

        if zero_count < 5:
            for task in task_list:
                ptr = task+offset
                val = mem_utils.readWord(cpu, ptr)
                if val is not None:
                    #print('\ttask 0x%x offset %d has unique value 0x%x' % (task, offset, val))
                    if offset not in retval:
                        retval.append(offset)
                else:
                    print('got None reading from 0x%x' % ptr)
    return retval


def compareOffsets(off1, off2):
    pfile1 = 'head-%d.pickle' % off1
    task_list1 = pickle.load(open(pfile1, 'rb'))
    pfile2 = 'head-%d.pickle' % off2
    task_list2 = pickle.load(open(pfile2, 'rb'))
    for i in range(len(task_list1)):
        print('off1 task 0x%x  off2: 0x%x' % (task_list1[i], task_list2[i]))

def dogmeat(cpu, mem_utils, off):
    pfile = 'head-%d.pickle' % off
    task_list = pickle.load(open(pfile, 'rb'))
    print('len task_list %d' % len(task_list))
    got = []
    for task in task_list:
        ptr = task + off
        val = mem_utils.readWord(cpu, ptr)
        if val in got:
            print('already got 0x%x' % val)
            break
        else:
           got.append(val)
    print('len of got is %d' % len(got))

def walkTasks(cpu, mem_utils, task, offset, smallest_record_size):
    retval = True
    #pfile = 'head-%d.pickle' % offset
    #print('Unique for offset %d' % offset)
    #task_list = pickle.load(open(pfile, 'rb'))
    head = task + offset
    done = False
    got = []
    heads = []
    prev_task = None
    print('start task 0x%x offset %d' % (task, offset))
    cur_task = task
    while not done: 
        next_rec_ptr = cur_task + offset + 8
        next_head = mem_utils.readPtr(cpu, next_rec_ptr)
        cur_task = next_head - offset
        print('cur_task now 0x%x next_head 0x%x' % (cur_task, next_head))
        if cur_task not in got:
            got.append(cur_task)
            #if cur_task not in task_list:
            #    print('0x%x not in task list' % cur_task)
        else:
            print('walkTasks already saw 0x%x' % cur_task)
            break
        if prev_task is not None:
            delta = abs(prev_task - cur_task)
            if delta < smallest_record_size:
                print('walkTasks with offset %d led to small record sizes' % offset)
                retval = False
                break
        prev_task = cur_task
    return retval

def findPid(cpu, mem_utils, offsets, best_offset, task_list): 
    retval = None
    #pfile = 'head-%d.pickle' % best_offset
    #task_list = pickle.load(open(pfile, 'rb'))
    for offset in offsets:
        too_big = False
        for task in task_list:
            ptr = task + offset
            val = mem_utils.readWord(cpu, ptr)
            if val > 0xffff:
                too_big = True
                break
        if not too_big:
            print('PID at offset %d' % offset)
            retval = offset
    return retval

def dumpOffsets(cpu, mem_utils, offsets, task):
    for off in offsets:
        print('offset %d' % off)
        ptr = task + off
        ref_ptr = mem_utils.readPtr(cpu, ptr)
        if ref_ptr is not None and ref_ptr > 0xffff000000000000:
        
            b = mem_utils.readBytes(cpu, ref_ptr, 80)
            if b is not None:
                x = b.decode('utf-16le', errors='ignore')
                print('decoded %s' % x)
            '''
            byte_array = mem_utils.getBytes(cpu, 80, ref_ptr)
            if byte_array is not None and len(byte_array)>0:
                s = resimUtils.getHexDump(byte_array)
                print(s)
            '''
   
def findString(cpu, mem_utils, task): 
    num_words = 158
    for i in range(num_words):
        offset = i*8
        ptr = task + offset
        ref_ptr = mem_utils.readPtr(cpu, ptr)
        if ref_ptr is not None and ref_ptr > 0xffff000000000000:
            b = mem_utils.readBytes(cpu, ref_ptr, 80)

            if b is not None:
                x = b.decode('utf-16', errors='ignore')
                print('decoded %s' % x)
    
   
def findParams(cpu, mem_utils, task_list, param):
    head_list = []
    first_task, record_sizes  = findRecordSize(cpu, mem_utils, task_list)
    bad_tasks = []
    task_maybe = []
    smallest_record_size = 0xfffffffff
    for size in record_sizes[:4]:
        task1, task2 = findAdjacentRecords(cpu, mem_utils, size, task_list)
        if size < smallest_record_size:
            smallest_record_size = size
        print('first task 0x%x, record_size 0x%x (%d) found %d adjacents' % (first_task, size, size, len(task1)))
        #for i in range(len(task1)):
        #    print('Adjacent task1 0x%x task2 0x%x' % (task1[i], task2[i]))
        #showRecordStarts(cpu, mem_utils, task_list)
        for i in range(len(task1)):
            delta = task2[i] - task1[i]
            print('Adjacent task1 0x%x task2 0x%x delta: %d' % (task1[i], task2[i], delta))
            heads = findHeads(cpu, mem_utils, task1[i], task2[i])
            if len(heads) == 0 and task1 not in bad_tasks:
                bad_tasks.append(task1[i])
            elif task1[i] not in task_maybe:
                task_maybe.append(task1[i])     
            for head in heads:
                print('\t\tHead offset %d' % head)
                if head not in head_list:
                    head_list.append(head)
    print('Smallest record size: %d' % smallest_record_size)   
    for head in head_list:
        print('head %d 0x%x' % (head, head))
    ''' smallest offset seems to be a deadwood list '''
    new_head_list = sorted(head_list)[1:]
    good_tasks = []
    for task in task_maybe:
        if task not in bad_tasks:
            print('maybe task 0x%x' % task)
            good_tasks.append(task) 
    got_tasks = {} 
    most_recs = 0
    best_task = None
    best_offset = None
    for task in good_tasks:
        record_count, task_matches, got_tasks[task] = walkList(cpu, mem_utils, task, new_head_list, task_list)
        for offset in record_count:
            if record_count[offset] > 10 and task_matches[offset] > 5:
                if record_count[offset] > most_recs:
                    most_recs = record_count[offset]
                    best_task = task
                    best_offset = offset
    best_task_list = got_tasks[best_task][best_offset]
    print('best task 0x%x, most recs %d best_offset %d' % (best_task, most_recs, best_offset))
    #pfile = 'head-%d.pickle' % best_offset
    #pickle.dump(got_tasks[best_task][best_offset], open(pfile, 'wb'))
    #walkTasks(cpu, mem_utils, best_task, best_offset)
    #compareOffsets(760, 1064)
    unique_offsets = findUnique(cpu, mem_utils, best_offset, best_task_list) 
    pid = findPid(cpu, mem_utils, unique_offsets, best_offset, best_task_list)
    #dumpOffsets(cpu, mem_utils, unique_offsets, best_task) 
    #findString(cpu, mem_utils, best_task)
    param.ts_pid = pid
    param.ts_next = best_offset+8
    param.ts_prev = best_offset

