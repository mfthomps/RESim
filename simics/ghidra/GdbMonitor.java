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

import generic.json.*;
import java.util.*;

public class GdbMonitor extends GhidraScript {
        protected int ndx=0; 
        protected GdbManagerImpl impl;
	@Override
	protected void run() throws Exception {
                String cmd;
                CompletableFuture<String> future;
                impl = getGdbManager();
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
                while(currentTrace == null){
		    currentTrace = traces.getCurrentTrace();
                    if(currentTrace == null){
                        println("no current trace, wait a sec");
                        Thread.sleep(1000);
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
                println("did mapping for start "+start+" length "+length);
        }
        protected void parseSO(String all_string){
            println("in parseSO\n");
            Object obj = getJson(all_string);
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
        protected Object getJson(String all_string){
            int start = all_string.indexOf('{'); 
            if(start < 0){
                println("Error, failed to get SO json");
                return null;
            }
            int end = all_string.lastIndexOf('}')+1;
            String jstring = all_string.substring(start, end);
            //println("in getJson string "+jstring);
            char[] console_char = jstring.toCharArray();
                JSONParser parser = new JSONParser();
		List<Object> objs = new ArrayList<Object>();
		List<JSONToken> tokens = new ArrayList<JSONToken>();
	
		JSONError r = parser.parse(console_char, tokens);
  		switch(r){
  		case JSMN_SUCCESS:
  			break;
  		case JSMN_ERROR_NOMEM:
  			println("out of memory");
  			return null;
  		case JSMN_ERROR_INVAL:
  			println("invalid json input");
  			return null;
  		case JSMN_ERROR_PART:
  			println("incomplete json input");
  			return null;
  		default:
  			println("json parser returned undefined status");
  			return null;
  		}
  		if(tokens.get(0).start == -1){
  			println("invalid json input");
  			return null;
  		}
                println("len of tokens is "+tokens.size());
                ndx = 0;
                JSONParser parser2 = new JSONParser();
                // Ghidra json parser does not let you reset internal ndx value; so hack is to create a 2nd parser.
  		Object obj = parser2.convert(console_char, tokens);
                println("returning obj from getJson len of objs is ");
                return obj;
        }     

        private GdbManagerImpl getGdbManager() throws Exception {
            DebuggerObjectsPlugin objects =
                (DebuggerObjectsPlugin) state.getTool().getService(ObjectUpdateService.class);
            DebuggerModelService models = objects.modelService;
            GdbModelImpl model = models.getModels()
                .stream()
                .filter(GdbModelImpl.class::isInstance)
                .map(GdbModelImpl.class::cast)
                .findFirst()
                .orElse(null);
            if (model == null) {
                return null;
            }
            Field f = GdbModelImpl.class.getDeclaredField("gdb");
            f.setAccessible(true);
            return (GdbManagerImpl) f.get(model);
        }
}

