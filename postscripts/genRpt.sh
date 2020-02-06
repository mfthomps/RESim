#
#  Do postprocessing on trace files.  Run from 
#  the postScripts directory, providing path to syscall_trace.txt directory
#
./netLinks.py $1 > $1/netlinks.txt
./ipcLinks.py $1 > $1/ipcLinks.txt
./fileLinks.py $1 > $1/filelinks.txt
