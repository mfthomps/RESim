#!/usr/bin/expect -f
# read the simics eula
#
spawn ./simics
expect {
     "Press return to continue" {
          send "\n"
          exp_continue
     }
     "Accept license" {
          sleep 2
          send "yes\n"
          exp_continue
     }
     "simics>" {
          send "quit"
     }
     default {
          send "\n"
          exp_continue
     }
}
