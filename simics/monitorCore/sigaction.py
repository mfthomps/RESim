# Linux sigaction sa_flags bit definitions
SA_FLAGS = {
    0x00000001: "SA_NOCLDSTOP",
    0x00000002: "SA_NOCLDWAIT",
    0x00000004: "SA_SIGINFO",
    0x04000000: "SA_RESTORER",
    0x08000000: "SA_ONSTACK",
    0x10000000: "SA_RESTART",
    0x20000000: "SA_NODEFER",
    0x40000000: "SA_RESETHAND",
}

def decodeFlags(flags): 
    """Decodes the Linux rt_sigaction sa_flags field into a human-readable list."""
    decoded = []
    
    # Iterate through all flag values and check if they are set
    for mask, name in SA_FLAGS.items():
        if flags & mask:
            decoded.append(name)
            
    # Handle obsolete/synonym masks that share the same bit values
    if flags & 0x00000001 and "SA_NOCLDSTOP" not in decoded:
        decoded.append("SA_NOCLDSTOP")
        
    return decoded

