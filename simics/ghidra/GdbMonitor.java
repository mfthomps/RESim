/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License atx
 * 
 *      http://www.apache.org/licenses/LICENS E-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//
// Connect to Simics and get the SOMap from RESim and use it to sync static and dynamic listings
//
//@category RESim
import com.google.common.collect.Range;
import java.util.concurrent.CompletableFuture;

import ghidra.app.script.GhidraScript; 
import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.DefaultTraceLocation;
import ghidra.trace.model.Trace;
import ghidra.util.database.UndoableTransaction;
import agent.gdb.manager.impl.GdbManagerImpl;
import agent.gdb.model.impl.GdbModelImpl;
import agent.gdb.manager.impl.cmd.GdbConsoleExecCommand.CompletesWithRunning;

import java.lang.reflect.Field;
import java.lang.Thread;

import ghidra.app.plugin.core.debug.gui.objects.DebuggerObjectsPlugin;
import ghidra.app.plugin.core.debug.gui.objects.ObjectUpdateService;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.DebuggerModelService;
import ghidra.util.NumericUtilities;

import java.util.*;
import resim.utils.RESimUtils;
import resim.utils.Json;

public class GdbMonitor extends GhidraScript {
        protected int ndx=0; 
        protected GdbManagerImpl impl;
	@Override
	protected void run() throws Exception {
                String cmd;
                CompletableFuture<String> future;
                RESimUtils ru = new RESimUtils(state.getTool(), currentProgram);
                impl = ru.getGdbManager();
                if(impl == null){
                    println("Failed to get gdbManager.");
                    return;
                }

                String remote = askString("Remote server?", "Enter host of remote server:");
                cmd = "target remote "+remote+":9123";
                future = impl.consoleCapture(cmd, CompletesWithRunning.CANNOT);
                String result = future.get();
                println("Result of target command is "+result);

                cmd = "monitor @cgc.getSOMap()";
                future = impl.consoleCapture(cmd, CompletesWithRunning.CANNOT);
                String so_json = future.get();
                parseSO(so_json);

	}
        protected void doMapping(Long start, Long end) throws Exception{
                println("in doMapping\n");
                Long length = end - start;
		DebuggerStaticMappingService mappings =
			state.getTool().getService(DebuggerStaticMappingService.class);
		DebuggerTraceManagerService traces =
			state.getTool().getService(DebuggerTraceManagerService.class);
                
		Trace currentTrace = null;
                int failcount = 0;
                while(currentTrace == null){
		    currentTrace = traces.getCurrentTrace();
                    if(currentTrace == null){
                        println("no current trace, wait a sec");
                        Thread.sleep(1000);
                        failcount++;
                        if(failcount > 10){
                            return;
                        }
                    } 
                }
		AddressSpace dynRam = currentTrace.getBaseAddressFactory().getDefaultAddressSpace();
		AddressSpace statRam = currentProgram.getAddressFactory().getDefaultAddressSpace();

		try (UndoableTransaction tid =
			UndoableTransaction.start(currentTrace, "Add Mapping", true)) {
			mappings.addMapping(
				new DefaultTraceLocation(currentTrace, null, Range.atLeast(0L),
					dynRam.getAddress(start)),
				new ProgramLocation(currentProgram, statRam.getAddress(start)),
				length, false);
		}
                println("did mapping for start "+String.format("0x%08X", start)+" length "+length);
        }
        protected void parseSO(String all_string){
            println("in parseSO\n");
            Object obj = Json.getJson(all_string);
            if(obj == null){
                println("Error getting json of somap");
                return;
            }
            java.util.HashMap<Object, Object> somap = (java.util.HashMap<Object, Object>) obj;
             
            println("did hash parseSO\n");
            println("size of hashmap is "+ somap.size());

            Long pid_o = (Long) somap.get("group_leader"); 
            println("in parseSO pid_o is "+pid_o);
            Long start = (Long) somap.get("prog_start");
            Long end = (Long) somap.get("prog_end");
            try{
                doMapping(start, end);
                println("did call doMapping");
            }catch(java.lang.Exception e){
                println("Error thrown by doMapping\n"+e.toString());
                e.printStackTrace();
            }
        }

}

