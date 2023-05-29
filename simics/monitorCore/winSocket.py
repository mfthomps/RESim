'''
AFD_CONNECT:  0x12007 
		
AFD_BIND:  0x12003 
		
AFD_RECV:  0x12017
		
AFD_SEND:  0x1201f 
		
AFD_ACCEPT: 0x12010 
		
AFD_SELECT: 0x12024 
		
AFD_SEND_DATAGRAM:  0x12023 
'''
op_map_vals = {}
op_map_vals['CONNECT'] = 0x12007
op_map_vals['BIND'] = 0x12003
op_map_vals['RECEIVE'] = 0x12017
op_map_vals['SEND'] = 0x1201f
op_map_vals['ACCEPT'] = 0x12010
op_map_vals['SELECT'] = 0x12024
op_map_vals['SEND_DATAGRAM'] = 0x12023
op_map = {}
op_map[0x12007] = 'CONNECT'
op_map[0x12003] = 'BIND'
op_map[0x12017] = 'RECEIVE'
op_map[0x1201f] = 'SEND'
op_map[0x12010] = 'ACCEPT'
op_map[0x12024] = 'SELECT'
op_map[0x12023] = 'SEND_DATAGRAM'
sock_operations = [0x12007, 0x12003, 0x12017, 0x1201f, 0x12010, 0x12024, 0x12023]
