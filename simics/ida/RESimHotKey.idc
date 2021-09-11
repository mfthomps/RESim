/*
Intended to be run with the -S option to IDA, this will set
a hotkey for "R" to run the runRESim.idc script.
*/
#include <idc.idc>
//#include </eems_images/cgc-monitor/RESim/simics/ida/runRESim.idc>
#include <runRESim.idc>
static main(){
    AddHotkey("Shift-R", "runRESim");
}
