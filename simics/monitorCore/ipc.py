SEMOP            =1
SEMGET           =2
SEMCTL           =3
SEMTIMEDOP       =4
MSGSND          =11
MSGRCV          =12
MSGGET          =13
MSGCTL          =14
SHMAT           =21
SHMDT           =22
SHMGET          =23
SHMCTL          =24
call = {}
call[1]='SEMOP'
call[2]='SEMGET'
call[3]='SEMCTL'
call[4]='SEMTIMEDOP'
call[11]='MSGSND'
call[12]='MSGRCV'
call[13]='MSGGET'
call[14]='MSGCTL'
call[21]='SHMAT'
call[22]='SHMDT'
call[23]='SHMGET'
call[24]='SHMCTL'

IPC_CREAT  =  0O00001000  
IPC_EXCL   =  0O00002000 
IPC_NOWAIT =  0O00004000

