from simics import *
'''

Powerpc 32 page table lookup.
'''
#
#  16 sr registers sr0 - sr15
#
import memUtils
class PtableInfo():
    def __init__(self, cpu, phys_addr, protect, nx):
        self.cpu = cpu
        self.page_base_addr = None
        # physical address including offset. 
        self.phys_addr = phys_addr
        self.protect = protect
        self.nx = nx 
        self.pteg1 = None
        self.pteg2 = None
    def valueString(self):
        if self.phys_addr is not None:
            retval =  'phys_addr: 0x%x nx: %s protect: %s' % (self.phys_addr, self.nx, self.protect)
        else:
            retval = 'page not valid'
        return retval

def getRegValue(cpu, reg):
    reg_num = cpu.iface.int_register.get_number(reg)
    value = cpu.iface.int_register.read(reg_num)
    return value

def rBitRange(value, s, e, bc):
    s = bc - s - 1
    e = bc - e - 1
    return memUtils.bitRange(value, e, s)

def rTestBit(value, s, bc):
    s = bc - s - 1
    return memUtils.testBit(value, s)

def getPTEG(hash1, sdr1, lgr):
    sdr1_0_6 = rBitRange(sdr1, 0, 6, 32) 
    
    n_0_8 = rBitRange(hash1, 0, 8, 19) 
    sdr_23_31 = rBitRange(sdr1, 23, 31, 32)
    n_0_8_and_sdr_23_31 = n_0_8 & sdr_23_31
    sdr1_7_15 = rBitRange(sdr1, 7, 15, 32)
    bracket = n_0_8_and_sdr_23_31 | sdr1_7_15
    #lgr.debug('pageUtilsPPC32 getPTEG bracket 0x%x' % bracket)
    
    n_9_18 = rBitRange(hash1, 9, 18, 19) << 6
    #lgr.debug('pageUtilsPPC32 getPTEG n_9_18 0x%x' % n_9_18)
    
    bracket_shifted = bracket << 16
    pteg_right = bracket_shifted | n_9_18
    #lgr.debug('pageUtilsPPC32 getPTEG pteg_right 0x%x' % pteg_right)
    pteg_left = sdr1_0_6 << 25
    #lgr.debug('pageUtilsPPC32 getPTEG sdr1_0_6 0x%x pteg_left 0x%x' % (sdr1_0_6, pteg_left))
    pteg = pteg_left | pteg_right
    return pteg

def findPTE(pteg, vsid, h, api, cpu, lgr):
    rpn = None
    pp = None
    retval = None, None, None
    pteg_addr = pteg
    valid_count = 0
    # TBD can we assume serial use of entries?
    for i in range(8):
        pte_high = SIM_read_phys_memory(cpu, pteg_addr, 4)
        pteg_addr += 4
        pte_low = SIM_read_phys_memory(cpu, pteg_addr, 4)
        pteg_addr += 4
        valid = rTestBit(pte_high, 0, 32)
        if valid != 0:
            valid_count += 1
            #lgr.debug('pageUtilsPPC32 fidnPTE pte low 0x%x high 0x%x' % (pte_low, pte_high))
            this_vsid = rBitRange(pte_high, 1, 24, 32)
            this_h = rTestBit(pte_high, 25, 32)
            this_api = rBitRange(pte_high, 26, 31, 32)
            #lgr.debug('pageUtilsPPC32 fidnPTE this_vsid 0x%x  this_h: 0x%x given_h: 0x%x this_api: 0x%x given_api 0x%x valid: %d' % (this_vsid, this_h, h, this_api, api, valid))
            if this_vsid == vsid and this_h == h and this_api == api:
                #lgr.debug('pageUtilsPPC32 fidnPTE this_vsid 0x%x  valid: %d  H: %d' % (this_vsid, valid, h))
                rpn = rBitRange(pte_low, 0, 19, 32)
                pp = rBitRange(pte_low, 30,31, 32)
                #lgr.debug('pageUtilsPPC32 fidnPTE rpn 0x%x pp 0x%x' % (rpn, pp))
                break 
    return rpn, pp

def findPageTable(cpu, ea, lgr):
    retval = None
    sdr1 = getRegValue(cpu, 'sdr1')
    #lgr.debug('EA 0x%x' % ea)
    sr = rBitRange(ea, 0, 3, 32)
    sr_reg = 'sr%d' % sr
    sr_reg_value = getRegValue(cpu, sr_reg)
    #lgr.debug('pageUtilsPPC32 findPageTable sr is %d reg: %s value: 0x%x' % (sr, sr_reg, sr_reg_value))
    page_index = rBitRange(ea, 4, 19, 32)
    api = rBitRange(page_index, 0, 5, 16)
    #lgr.debug('pageUtilsPPC32 findPageTable page_index 0x%x api: 0x%x' % (page_index, api))
    vsid = rBitRange(sr_reg_value, 8, 31, 32)
    nx = rTestBit(sr_reg_value, 3, 32)
    #lgr.debug('pageUtilsPPC32 findPageTable nx is %s' % nx)

    #lgr.debug('pageUtilsPPC32 findPageTable vsid 0x%x' % vsid)
    hash_key = (vsid << 8) | page_index
    #lgr.debug('pageUtilsPPC32 findPageTable hash_key 0x%x' % hash_key)
    htaborg = rBitRange(sdr1, 0, 15, 32)
    htabmask = rBitRange(sdr1, 23, 31, 32)
    #lgr.debug('pageUtilsPPC32 findPageTable sdr1 0x%x htaborg 0x%x htabmask 0x%x' % (sdr1, htaborg, htabmask))
    hash_in1 = rBitRange(vsid, 5, 23, 24)
    hash_in2 = rBitRange(ea, 4, 19, 32) 
    hash1 = hash_in1 ^ hash_in2
    #lgr.debug('pageUtilsPPC32 findPageTable hash_in1 0x%x hash_in2 0x%x hash1 0x%x' % (hash_in1, hash_in2, hash1))
    pteg = getPTEG(hash1, sdr1, lgr)
    #lgr.debug('pageUtilsPPC32 findPageTable pteg 0x%x' % pteg)
    first_pteg = pteg
    rpn, pp  = findPTE(pteg, vsid, 0, api, cpu, lgr)
    if rpn is None:
        hash2 = ~ hash1
        pteg = getPTEG(hash2, sdr1, lgr)
        #print('pteg 0x%x' % pteg)
        rpn, pp = findPTE(pteg, vsid, 1, api, cpu, lgr)
    if rpn is None:
        # TBD equivalent of page table entry?  This is very incomplete
        #lgr.debug('pageUtilsPPC32 findPageTable Failed to find PTE for addr 0x%x pteg1 0x%x pteg2 0x%x' % (ea, first_pteg, pteg))
        retval = PtableInfo(cpu, None, None, None) 
        retval.pteg1 = first_pteg
        retval.pteg2 = pteg
    else:
        #lgr.debug('pageUtilsPPC32 findPageTable rpn 0x%x pp 0x%x' % (rpn, pp))
        ra = None
        rpn_shifted = rpn << 12
        #lgr.debug('pageUtslisPPC32 rpn_shifted 0x%x nx now %s' % (rpn_shifted, nx))
        if rpn is not None:
            ra = (rpn << 12) | (ea & 0x00000fff)
        retval = PtableInfo(cpu, ra, pp, nx)
    return retval
