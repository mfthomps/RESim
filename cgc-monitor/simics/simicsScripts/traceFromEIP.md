% traceFromEIP (1) Cyber Grand Challenge Monitoring
% Mike Thompson <mfthomps@nps.edu>
% December 15, 2015
# NAME

traceFromEIP  -- Create an execution/data trace starting at a given EIP


# DESCRIPTION

Uses Simics to create an execution trace from a boot image,
starting at a specified EIP, and continuing for a given number
of machine cycles.  Note each intruction requires only one cycle,
and cycles are consumed by i/o.

    traceFromEIP.sh <EIP> <cycles>

The tool expects to find a traceTarget.craff Simics bootable image.
These images are created from vmdk files using:

    vmdkToCraff.sh <vmdk>

Where vmdk is the name of a vmdk file.  
**The vmdkToCraff.sh takes a long time (ten minutes).**


# COPYRIGHT
Created by employees of the US Government, cannot be copyrighted.

