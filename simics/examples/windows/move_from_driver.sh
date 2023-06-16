# source this
# This program is intended to be run from the driver.
# It will copy the simple_server.exe to the windows box from the driver.  Then run it in a manner that does not 
# kill the process when the shell disconnects.
#
cd /tmp/
scp -i id_rsa -o StrictHostKeyChecking=no simple_server.exe admin@10.10.0.100:C:\\Users\\admin\\simple_server.exe
ssh -i id_rsa -o StrictHostKeyChecking=no -C admin@10.10.0.100 "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList C:\Users\admin\simple_server.exe"

