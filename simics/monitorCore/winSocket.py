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

op_map_vals["ACCEPT"]= 0x12010 
op_map_vals["BIND"]= 0x12003 
op_map_vals["CONNECT"]= 0x12007 
op_map_vals["DEFER_ACCEPT"]= 0x1208F 
op_map_vals["DISCONNECT"]= 0x1202B 
op_map_vals["ENUM_NETWORK_EVENTS"]= 0x1208B 
op_map_vals["EVENT_SELECT"]= 0x12087 
op_map_vals["GET_CONNECT_DATA"]= 0x12057 
op_map_vals["GET_CONNECT_OPTIONS"]= 0x1205B 
op_map_vals["GET_CONTEXT"]= 0x1203F 
op_map_vals["GET_DISCONNECT_DATA"]= 0x1205F 
op_map_vals["GET_DISCONNECT_OPTIONS"]= 0x12063 
op_map_vals["GET_INFO"]= 0x1207B
op_map_vals["GET_PEER_NAME"]= 0x12033
op_map_vals["GET_PENDING_CONNECT_DATA"]= 0x120A7
op_map_vals["GET_SOCK_NAME"]= 0x1202F
op_map_vals["GET_TDI_HANDLES"]= 0x12037
op_map_vals["RECV"]= 0x12017
op_map_vals["RECV_DATAGRAM"]= 0x1201B
op_map_vals["SELECT"]= 0x12024
op_map_vals["SEND"]= 0x1201F
op_map_vals["SEND_DATAGRAM"]= 0x12023
op_map_vals["SET_CONNECT_DATA"]= 0x12047
op_map_vals["SET_CONNECT_DATA_SIZE"]= 0x1206B
op_map_vals["SET_CONNECT_OPTIONS"]= 0x1204B
op_map_vals["SET_CONNECT_OPTIONS_SIZE"]= 0x1206F
op_map_vals["SET_CONTEXT"]= 0x12043
op_map_vals["SET_DISCONNECT_DATA"]= 0x1204F
op_map_vals["SET_DISCONNECT_DATA_SIZE"]= 0x12073
op_map_vals["SET_DISCONNECT_OPTIONS"]= 0x12053
op_map_vals["SET_DISCONNECT_OPTIONS_SIZE"]= 0x12077
op_map_vals["SET_INFO"]= 0x1203B
op_map_vals["START_LISTEN"]= 0x1200B
op_map_vals["WAIT_FOR_LISTEN"]= 0x1200C
# from web
op_map_vals["TCP_FASTOPEN"]= 0x120BF
op_map_vals["SUPER_CONNECT"]= 0x120C7
#op_map_vals["SUPER_CONNECT2"]= 0x120CF
# from digging
op_map_vals["12083_ACCEPT"]=0x12083
op_map_vals["RANDOM_VALUE"]=0x390008
# from trial/error/google
op_map_vals["FSCTL_MARK_HANDLE"]=0x12000f


def getOpMap():
    retval = {}
    for op in op_map_vals:
        retval[op_map_vals[op]] = op
    return retval
