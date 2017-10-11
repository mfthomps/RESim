Readme for managing monitor repositories, which is data and
code collected on the development machine and put onto an NFS
share.  Slaves update themselves from the repositories as
part of their boostrapping.

On the development machine, run:
collectSlaveRepo.sh

The slaves run monitorSlaveBootstrap.sh to get this code/data.
