# This Software is part of Simics. The rights to copy, distribute,
# modify, or otherwise make use of this Software may be licensed only
# pursuant to the terms of an applicable license agreement.
# 
# Copyright 2010-2021 Intel Corporation

from cli import new_info_command, new_status_command

def info(obj):
    return [(None,
             [("I2C Device Address", obj.attr.address),
              ("I2C Bus", obj.attr.i2c_bus)])]

def status(obj):
    return [(None,
             [("Read Value", obj.attr.read_value),
              ("Written Value", obj.attr.written_value)])]

new_info_command("sample_i2c_device", info)
new_status_command("sample_i2c_device", status)
