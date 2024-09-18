class DataBuf():
    def __init__(self, addr, start_index):
        self.addr = addr
        self.start_index = start_index
        self.end_index = None
class FindRefs():
    def __init__(self, offset, watch_marks, lgr):
        self.watch_marks = watch_marks
        self.lgr = lgr
        self.findMarks(offset)

    def findMarks(self, offset):
        running_offset = 0
        buf_addr = None
        buf_list = []
        for mark in self.watch_marks:
            if 'mark_type' not in mark:
                self.lgr.error('mark_type not in mark %s' % str(mark))
                continue
            mark_index = mark['index'] + 1
            if mark['mark_type'] == 'call':
                if offset <= running_offset + mark['length'] - 1:
                    delta = offset - running_offset
                    buf_addr = mark['recv_addr']+delta
                    self.lgr.debug('found offset. running offset was 0x%x  recv addr was 0x%x delta 0x%x' % (running_offset, mark['recv_addr'], delta)) 
                    data_buf = DataBuf(buf_addr, mark_index)
                    buf_list.append(data_buf)
                    break
                else:
                    self.lgr.debug('found call of len 0x%x, but offset 0x%x not reached.  running_offset was 0x%x' % (mark['length'], offset, running_offset))
                    running_offset = running_offset + mark['length'] - 1
        if buf_addr is None:
            self.lgr.error('findRefs offset 0x%x not found in any call buffer' % offset)
        else:
            self.lgr.debug('findRefs offset 0x%x found at buf_addr 0x%x' % (offset, buf_addr)) 
            for mark in self.watch_marks:
                mark_index = mark['index'] + 1
                if mark['mark_type'] == 'copy':
                    copy_list = list(buf_list)
                    for data_buf in copy_list:
                        if data_buf.end_index is not None and data_buf.end_index < mark_index:
                            continue
                        addr = data_buf.addr
                        end = mark['src'] + mark['length']
                        if addr >= mark['src'] and addr <= end:
                            buf_offset = addr - mark['src']
                            dest = mark['dest'] + buf_offset
                            self.lgr.debug('findRefs found copy index %d from 0x%x to 0x%x' % (mark_index, addr, dest))
                            new_data_buf = DataBuf(dest, mark_index)
                            buf_list.append(new_data_buf)
                        else:
                            end = mark['dest'] + mark['length']
                            if addr >= mark['dest'] and addr <= end:
                                data_buf.end_index = mark_index-1
                                self.lgr.debug('findRefs copy overwrote index %d 0x%x set end index to %d' % (mark_index, addr, data_buf.end_index))
            for mark in self.watch_marks:     
                mark_index = mark['index'] + 1
                if mark['mark_type'] == 'read':
                    for data_buf in buf_list:
                        if data_buf.end_index is not None and data_buf.end_index < mark_index:
                            continue
                        addr = data_buf.addr
                        end = mark['addr'] + mark['trans_size'] - 1
                        if addr >=  mark['addr'] and addr <= end:
                            self.lgr.debug('findRefs addr 0x%x  end 0x%x read mark[addr] 0x%x' % (addr, end, mark['addr']))
                            print('Watchmark %d read offset 0x%x at address 0x%x' % (mark_index, offset, addr))
