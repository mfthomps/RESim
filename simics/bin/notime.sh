#
# sed out time and polling noise from a RESim syscall trace file
#
sed '/gettimeofday/d;/nanosleep/d;/epoll_wait/d;/settime/d;/wait4/d' $1
