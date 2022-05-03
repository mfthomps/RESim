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
import agent.gdb.manager.impl.GdbManagerImpl;
import agent.gdb.manager.impl.cmd.GdbConsoleExecCommand.CompletesWithRunning;

import ghidra.app.script.GhidraScript;

import java.util.*;
import resim.utils.RESimUtils;

public class GdbMonitor extends GhidraScript {
        protected int ndx=0; 
        protected GdbManagerImpl impl;
	@Override
	protected void run() throws Exception {
                String cmd;
                CompletableFuture<String> future;
                String result=null;
                RESimUtils ru = new RESimUtils(state.getTool(), currentProgram);
                impl = ru.getGdbManager();
                if(impl == null){
                    println("Failed to get gdbManager.");
                    return;
                }

                String remote = askString("Remote server?", "Enter host of remote server:");
                cmd = "target remote "+remote+":9123";
                try{
                    future = impl.consoleCapture(cmd, CompletesWithRunning.CANNOT);
                    result = future.get();
                }catch(Exception e){
                    println("Error connecting to "+remote);
                    return;
                }
                println("Result of target command is "+result);
                ru.doMapping();

	}

}

