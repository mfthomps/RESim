/*
Run the RESim IDA client.  This function is intended to be invoked via
a hotkey, and is intended to reside in the IDA/idc directory.
*/
static runRESim(){
   auto path = eval_python("os.getenv('RESIM_DIR')");
   auto pypath = sprintf("exec(open('%s/simics/ida/runsFirst.py').read())", path);
   //auto pypath = sprintf("execfile('%s/simics/ida/runsFirst.py')", path);
   eval_python(pypath);
}
