import pickle
import resimUtils
from simics import *
'''
Routines to tease out Windows 7 kernel parameters for use by RESim
Assumes a task_list obtained by watching the current task
pointer. Note this list was dynamically created and will not necessarily
match the single state of the current machine, e.g., tasks may have been
created and deleted.
'''
comm_offset = 0x2e0
proc_ptr_offset = 0x210
def findRecordSize(cpu, mem_utils, task_list, lgr):
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
            if delta < least and delta > 100:
                least = delta
        #print('least is 0x%x' % least)
        lgr.debug('findRecordSize task 0x%x least is 0x%x' % (task, least))
        if least not in retval:
            retval.append(least)
    lgr.debug('first_task 0x%x size 0x%x' % (first_task, record_size))
    return first_task, sorted(retval)

def showRecordStarts(cpu, mem_utils, orig_task_list):
    #orig_task_list = pickle.load(open('task_list.pickle', 'rb'))
    task_list = sorted(orig_task_list)[3:150]
    prev = None
    delta = 0
    for task in task_list:
        if prev is not None:
            delta = task - prev
        print('task: 0x%x delta 0x%x' % (task, delta))
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

def walkList(cpu, mem_utils, task, offsets, orig_task_list, smallest_record_size, pid_offset, lgr):
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
                #lgr.debug('already got')
                break
            else:
                got.append(task_ptr)
                #lgr.debug('append got 0x%x' % task_ptr)
            pid = mem_utils.readWord32(cpu, task_ptr+pid_offset)
            if pid == 0:
                lgr.debug('got pid 0')
                break
        if match_count > 1 and len(got) > 5:
            lgr.debug('walk list task 0x%x offset %d' % (task, head_off))
            walkTasks(cpu, mem_utils, task, head_off, smallest_record_size, pid_offset, lgr)
            if True:
                print('walkList task 0x%x offset %d walked(got) %d records, with %d matches in task_list' % (task, head_off, len(got), match_count))
                lgr.debug('walkList task 0x%x offset %d walked(got) %d records, with %d matches in task_list' % (task, head_off, len(got), match_count))
                record_count[head_off] = len(got)
                task_matches[head_off] = match_count
                got_tasks[head_off] = got
    return record_count, task_matches, got_tasks


def findHeads(cpu, mem_utils, task1, task2, lgr):
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
    lgr.debug('findHeads for adjacent tasks 0x%x and 0x%x, delta %d 0x%x' % (task1, task2, delta, delta))
    lgr.debug('cur 0x%x  task2: 0x%x' % (cur, task2))
    while cur < task2:
        val = mem_utils.readWord(cpu, cur)
        if val >= task2 and val <= (task2+num_words*8):
            ''' think val is pointing to a HEAD struct '''
            head_offset = t1offset - 8
            print('findHeads read from 0x%x (%d bytes from task1 0x%x) value 0x%x' % (cur, t1offset, task1, val))
            lgr.debug('findHeads read from 0x%x (%d bytes from task1 0x%x) value 0x%x' % (cur, t1offset, task1, val))
            task2_guess = val - head_offset
            if task2_guess == task2:
                print('\tguess matches task2, single pointer?')
                lgr.debug('\tguess matches task2, single pointer?')
                retval.append(head_offset)
            else:
                print('\tguess is %d bytes short' % ((task2-task2_guess)))
                lgr.debug('\tguess is %d bytes short' % ((task2-task2_guess)))

            #t2offset = val - task2 
            #print('\ttask1 offset %d val 0x%x points into task2 offset %d' % (t1offset, val, t2offset)) 
            #val2 = mem_utils.readWord(cpu, val)
            #print('\ttask2 points to 0x%x ' % val2)
            #val3 = mem_utils.readWord(cpu, (val+8))
            #print('\ttask2 next? points to 0x%x ' % val3)
        t1offset = t1offset+8 
        cur = task1 + t1offset
    return retval
  
def findUnique(cpu, mem_utils, offset, task_list, rec_size, pid_offset, lgr): 
    #task_list = pickle.load(open('head-768.pickle', 'rb'))
    #pfile = 'head-%d.pickle' % offset
    #print('Unique for offset %d' % offset)
    #task_list = pickle.load(open(pfile, 'rb'))
    words = {}
    dup_words = []
    delta = 0
    prev = None
    #val_size = 4
    val_size = 2
    rec_size = min(rec_size, 2000)
    num_words = int(rec_size/val_size)
    retval = []
    for i in range(num_words):
        words[i] = []
    lgr.debug('findUnique rec size %d, %d words' % (rec_size, num_words))

    #look_for = offset + 8
    look_for = offset + val_size

    for task in task_list:
        #print('task 0x%x' % cur)
        for i in range(num_words):
            if i in dup_words: 
                continue
            off = i*val_size
            cur = task + off
            val = mem_utils.readWord32(cpu, cur)
            if val not in words[i]:
                words[i].append(val)
            elif val != 0:
                if i not in dup_words:
                    dup_words.append(i) 
    

    for i in range(num_words):
        if i in dup_words:
            continue
        offset = i*val_size
        zero_count = 0
        for task in task_list:
            ptr = task+offset
            val = mem_utils.readWord32(cpu, ptr)
            if val == 0:
                zero_count += 1

        #if zero_count < 50:
        if zero_count < 5:
            for task in task_list:
                ptr = task+offset
                val = mem_utils.readWord32(cpu, ptr)
                if val is not None:
                    print('\ttask 0x%x offset %d has unique value 0x%x (%d)' % (task, offset, val, val))
                    lgr.debug('\ttask 0x%x offset %d has unique value 0x%x (%d)' % (task, offset, val, val))
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

def walkTasks(cpu, mem_utils, task, offset, smallest_record_size, pid_offset, lgr):
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
    lgr.debug('start task 0x%x offset %d' % (task, offset))
    cur_task = task
    while not done: 
        next_rec_ptr = cur_task + offset 
        next_head = mem_utils.readPtr(cpu, next_rec_ptr)
        cur_task = next_head - offset
        comm = mem_utils.readString(cpu, cur_task+comm_offset, 16)
        pid = mem_utils.readWord32(cpu, cur_task+pid_offset)
        print('cur_task now 0x%x next_head 0x%x comm %s pid %d' % (cur_task, next_head, comm, pid))
        lgr.debug('cur_task now 0x%x next_head 0x%x comm %s pid %d' % (cur_task, next_head, comm, pid))
        if cur_task not in got:
            got.append(cur_task)
            #if cur_task not in task_list:
            #    print('0x%x not in task list' % cur_task)
        else:
            print('walkTasks already saw 0x%x' % cur_task)
            log.debug('walkTasks already saw 0x%x' % cur_task)
            break
        if prev_task is not None:
            delta = abs(prev_task - cur_task)
            if delta < smallest_record_size:
                print('walkTasks with offset %d led to small record sizes' % offset)
                lgr.debug('walkTasks with offset %d led to small record sizes' % offset)
                retval = False
                break
        prev_task = cur_task
        if pid == 0:
            break
    return retval

def findPid(cpu, mem_utils, offsets, best_offset, task_list, lgr): 
    retval = None
    #pfile = 'head-%d.pickle' % best_offset
    #task_list = pickle.load(open(pfile, 'rb'))
    too_big_count = 0
    lgr.debug('findPid')
    for offset in offsets:
        lgr.debug('findPid offset %d' % offset)
        too_big = False
        for task in task_list:
            ptr = task + offset
            val = mem_utils.readWord(cpu, ptr)
            if val > 0xffff:
                too_big_count = too_big_count + 1
        if too_big_count < 2:
            print('PID at offset %d  but %d too big' % (offset, too_big_count))
            lgr.debug('PID at offset %d  but %d too big' % (offset, too_big_count))
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
    
def getNewTaskList(task_list, mem_utils, cpu):
    retval = []
    for task in task_list:
        ptr = task + proc_ptr_offset
        ref_ptr = mem_utils.readPtr(cpu, ptr)
        if ref_ptr not in retval:
            retval.append(ref_ptr)
    return retval

def hackpid(cpu, mem_utils, task_list, lgr, max_zeros=5):
    words = {}
    dup_words = []
    delta = 0
    prev = None
    #val_size = 4
    val_size = 2
    rec_size = 2000
    num_words = int(rec_size/val_size)
    lgr.debug('hackpid numwords %d num_tasks: %d' % (num_words, len(task_list)))
    retval = []
    for i in range(num_words):
        offset = i*val_size
        words[offset] = []
    for offset in words:
        zero_count = 0
        for task in task_list:
            cur_ptr = task + offset
            val = mem_utils.readWord32(cpu, cur_ptr)
            #print('offset %d val %d' % (offset, val))
            if val is not None:
                lgr.debug('hackpid offset %d val %d' % (offset, val))
                if val not in words[offset]:
                    lgr.debug('hackpid words[%d] append %d' % (offset, val))
                    words[offset].append(val)
                else:
                    if val == 0 and zero_count < max_zeros:
                        zero_count = zero_count + 1
                        pass 
                    else:
                        lgr.debug('val %d already in words[%d]  break' % (val, offset))
                        dup_words.append(offset)
                        break
            else:
                lgr.debug('hackpid val was zero at ptr 0x%x' % cur_ptr)
    lgr.debug('hackpid got %d dupwords' % len(dup_words))      
    too_big = [] 
    for offset in words:
        if offset in dup_words:
            continue
        else:
            for value in words[offset]:
                #print('Unique offset 0x%x value %d' % (offset, value)) 
                lgr.debug('Unique offset 0x%x value %d' % (offset, value)) 
                if value > 0xffff:
                    too_big.append(offset)
    lgr.debug('Now find smallest offset')
    smallest_offset = None
    for offset in words:
        if offset in too_big or offset in dup_words:
            continue
        else:
            if smallest_offset is None:
                smallest_offset = offset
            for value in words[offset]:
                print('Smallish Unique offset 0x%x value %d' % (offset, value)) 
                lgr.debug('Smallish Unique offset 0x%x value %d' % (offset, value)) 
    print('Smallest offset is %d (0x%x)' % (smallest_offset, smallest_offset))
    return smallest_offset
    
def getCurTaskRec(cpu, mem_utils, param, current_task_phys, lgr):
    retval = None
    cur_thread = SIM_read_phys_memory(cpu, current_task_phys, 8)
    if cur_thread is None:
        lgr.error('winTaskUtils getCurTaskRec got cur_thread of None reading 0x%x' % current_task_phys)
    else:
        ptr = cur_thread + param.proc_ptr
        phys = mem_utils.v2p(cpu, ptr)
        lgr.debug('getCurTaskRec cur_thread 0x%x  proc_addr 0x%x phys 0x%x' % (cur_thread, ptr, phys))
        retval = SIM_read_phys_memory(cpu, phys, 8)
        
    return retval


def walk(cpu, mem_utils, param, task_ptr_in, lgr):
        done = False
        got = []
        task_ptr = task_ptr_in
        offset = param.ts_next
        lgr.debug('winTaskUtils walk task_ptr 0x%x offset 0x%x ts_pid: 0x%x' % (task_ptr, offset, param.ts_pid))
        while not done:
            pid_ptr = mem_utils.getUnsigned(task_ptr + param.ts_pid)
            lgr.debug('winTaskUtils walk got pid_ptr 0x%x from task_ptr 0x%x plus ts_pid' % (pid_ptr, task_ptr))
            pid = mem_utils.readWord(cpu, pid_ptr)
            if pid is not None:
                got.append(task_ptr)
                lgr.debug('winTaskUtils walk got pid %d from task_ptr 0x%x' % (pid, task_ptr))
            else:
                lgr.debug('got no pid for pid_ptr 0x%x' % pid_ptr)
                print('got no pid for pid_ptr 0x%x' % pid_ptr)
                break
            task_next = mem_utils.getUnsigned(task_ptr + offset)
            val = mem_utils.readWord(cpu, task_next)
            if val is None:
                print('died on task_next 0x%x' % task_next)
                break
            else:
                next_head = mem_utils.getUnsigned(val)
            
            task_ptr = next_head - param.ts_prev
            task_ptr = mem_utils.getUnsigned(task_ptr)
            #lgr.debug('winTaskUtils got new task_ptr 0x%x from next_head of 0x%x' % (task_ptr, next_head))
            if task_ptr in got:
                #print('already got task_ptr 0x%x' % task_ptr)
                #lgr.debug('walk already got task_ptr 0x%x' % task_ptr)
                break
        return got


def findParams(cpu, mem_utils, task_list, param, current_task_phys, lgr):
    # TBD fix this
    param.ts_comm = comm_offset
    param.proc_ptr = proc_ptr_offset
    param.ts_pid = 384
    param.ts_next = 952
    param.ts_prev = 944
    # offset of user space page table base (cr3)
    param.page_table = 0x28

    return

    cur_task = getCurTaskRec(cpu, mem_utils, param, current_task_phys, lgr)
    walk(cpu, mem_utils, param, cur_task, lgr)

    ''' TBD fix with saner approach taking advantage of what we know about head lists rather than
        looking for adjacent records, which is a loser'''
    new_task_list = getNewTaskList(task_list, mem_utils, cpu)
    print('Got %d tasks from %d collected current task values' % (len(new_task_list), len(task_list)))
    lgr.debug('Got %d tasks from %d collected current task values' % (len(new_task_list), len(task_list)))
    for task in new_task_list:
            comm = mem_utils.readString(cpu, task+comm_offset, 16)
            print('comm is %s' % comm)
            lgr.debug('comm is %s' % comm)
    pid_offset = hackpid(cpu, mem_utils, new_task_list, lgr) 
    lgr.debug('hackpid got pid offset of %d (0x%x)' % (pid_offset, param.ts_pid)) 
    
    param.ts_pid = pid_offset

 
    head_list = []
    first_task, record_sizes  = findRecordSize(cpu, mem_utils, new_task_list, lgr)
    bad_tasks = []
    task_maybe = []
    smallest_record_size = 0xfffffffff
    for size in record_sizes[:4]:
        task1, task2 = findAdjacentRecords(cpu, mem_utils, size, new_task_list)
        if size < smallest_record_size:
            smallest_record_size = size
        print('first task 0x%x, record_size 0x%x (%d) found %d adjacents' % (first_task, size, size, len(task1)))
        lgr.debug('first task 0x%x, record_size 0x%x (%d) found %d adjacents' % (first_task, size, size, len(task1)))
        #for i in range(len(task1)):
        #    print('Adjacent task1 0x%x task2 0x%x' % (task1[i], task2[i]))
        #showRecordStarts(cpu, mem_utils, task_list)
        for i in range(len(task1)):
            delta = task2[i] - task1[i]
            print('Adjacent task1 0x%x task2 0x%x delta: %d' % (task1[i], task2[i], delta))
            lgr.debug('Adjacent task1 0x%x task2 0x%x delta: %d' % (task1[i], task2[i], delta))
            heads = findHeads(cpu, mem_utils, task1[i], task2[i], lgr)
            lgr.debug('returned %d heads' % len(heads))
            if len(heads) == 0 and task1 not in bad_tasks:
                bad_tasks.append(task1[i])
            elif task1[i] not in task_maybe:
                task_maybe.append(task1[i])     
            for head in heads:
                print('\t\tHead offset %d' % head)
                if head not in head_list:
                    head_list.append(head)

    lgr.debug('Smallest record size: %d' % smallest_record_size)   
    print('Smallest record size: %d' % smallest_record_size)   
    for head in head_list:
        print('head %d 0x%x' % (head, head))
        lgr.debug('head %d 0x%x' % (head, head))
    #''' smallest offset seems to be a deadwood list '''
    new_head_list = sorted(head_list)[1:]
    good_tasks = []
    for task in task_maybe:
        if task not in bad_tasks:
            print('maybe task 0x%x' % task)
            lgr.debug('maybe task 0x%x' % task)
            good_tasks.append(task) 
    got_tasks = {} 
    most_recs = 0
    best_task = None
    best_offset = None
    for task in good_tasks:
        record_count, task_matches, got_tasks[task] = walkList(cpu, mem_utils, task, new_head_list, new_task_list, smallest_record_size, param.ts_pid, lgr)
        lgr.debug('back from walkList task 0x%x len record_count %d task_matches %d' % (task, len(record_count), len(task_matches)))
        for offset in record_count:
            lgr.debug('from walkList task 0x%x offset %d len record_count %d task_matches %d' % (task, offset, record_count[offset], task_matches[offset]))
            if record_count[offset] > 10 and task_matches[offset] > 4:
                if record_count[offset] > most_recs:
                    most_recs = record_count[offset]
                    best_task = task
                    best_offset = offset
    best_task_list = got_tasks[best_task][best_offset]
    print('best task 0x%x, most recs %d best_offset %d' % (best_task, most_recs, best_offset))
    lgr.debug('best task 0x%x, most recs %d best_offset %d' % (best_task, most_recs, best_offset))
   
    param.ts_next = best_offset+8
    param.ts_prev = best_offset

