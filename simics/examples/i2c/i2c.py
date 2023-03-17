'''
Example python script that adds a sample-ic2-device to an
x86 i2c_link (created by platforms such as x56-ich10 to support the smb)

'''
SIM_run_command('load-module sample-i2c-device')
''' Assign address here '''
i2c_dev=SIM_create_object("sample_i2c_device", "s_i2c_device", [['address', 0xae]])
''' let the slave know about the link '''
i2c_dev.attr.i2c_link = conf.my.mb.sb.i2c_link

''' register the slave on the link'''
conf.my.mb.sb.i2c_link.iface.i2c_link.register_slave_address(conf.s_i2c_device, 0xae, 0xfffffffe)

SIM_run_command('my.mb.sb.i2c_link.log-level 4')
