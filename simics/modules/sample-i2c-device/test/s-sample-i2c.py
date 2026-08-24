# This Software is part of Simics. The rights to copy, distribute,
# modify, or otherwise make use of this Software may be licensed only
# pursuant to the terms of an applicable license agreement.
# 
# Copyright 2012-2021 Intel Corporation

# Test example for sample-i2c-device

import stest
import pyobj

# Fake I2C link
class fake_link(pyobj.ConfObject):
    '''Fake I2C link v2 class'''
    def _initialize(self):
        super()._initialize()
        self.reqs = []

    class i2c_master_v2(pyobj.Interface):
        def finalize(self):
            pass

        def acknowledge(self, ack):
            self._up.reqs.append(['ack', ack])

        def read_response(self, value):
            self._up.reqs.append(['read_response', value])

i2c_conf = pre_conf_object('i2c_dev', 'sample_i2c_device')
i2c_conf.attr.address = 0x20
i2c_link = pre_conf_object('i2c_link', 'fake_link')
i2c_conf.attr.i2c_link_v2 = i2c_link

SIM_add_configuration([i2c_conf, i2c_link], None)

i2c = conf.i2c_dev
link = conf.i2c_link

def test_start():
    # No valid checking of i2c addresses
    addresses = [0, 0x1, 0x11, 0x7e, 0x7f]
    for i2c_addr in addresses:
        for start_addr in addresses:
            i2c.address = i2c_addr >> 1
            i2c.iface.i2c_slave_v2.start(start_addr)
            stest.expect_equal(link.object_data.reqs[-1],
                               ['ack', (i2c_addr >> 1) != (start_addr >> 1)])

def test_read_write():
    read_val = 0x5a
    write_val = 0x17
    i2c.iface.i2c_slave_v2.write(write_val)
    stest.expect_equal(i2c.attr.written_value, write_val)
    stest.expect_equal(link.object_data.reqs[-1], ['ack', 0])

    i2c.attr.read_value = read_val
    i2c.iface.i2c_slave_v2.read()
    stest.expect_equal(link.object_data.reqs[-1], ['read_response', read_val])

test_start()
test_read_write()

print("All tests passed.")
