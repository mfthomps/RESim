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
// Use the RESim revToAddr function to reverse to the current cursor location.
//
//@category RESim
import com.google.common.collect.Range;
import java.util.concurrent.CompletableFuture;

import ghidra.app.script.GhidraScript; 
import ghidra.program.model.address.AddressSpace;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.trace.model.DefaultTraceLocation;
import ghidra.trace.model.Trace;
import ghidra.util.database.UndoableTransaction;
import agent.gdb.manager.impl.GdbManagerImpl;
import agent.gdb.model.impl.GdbModelImpl;
import agent.gdb.manager.impl.cmd.GdbConsoleExecCommand.CompletesWithRunning;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.app.plugin.core.debug.gui.objects.DebuggerObjectsProvider;

import java.lang.reflect.Field;

import ghidra.app.plugin.core.debug.gui.objects.DebuggerObjectsPlugin;
import ghidra.app.plugin.core.debug.gui.objects.ObjectUpdateService;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.DebuggerModelService;
import ghidra.util.NumericUtilities;
import ghidra.program.model.address.Address;

import generic.json.*;
import java.util.*;

public class RevToCursor extends GhidraScript {
        protected int ndx=0; 
        protected GdbManagerImpl impl;
	@Override
	protected void run() throws Exception {
                impl = getGdbManager();
                if(impl == null){
                    println("Failed to get gdbManager.");
                    return;
                }
                long laddr = currentAddress.getOffset();
                println("laddr is "+laddr);
                String cmd = "monitor @cgc.revToAddr("+laddr+")";
                println("cmd is "+cmd);
                CompletableFuture<String> future = impl.consoleCapture(cmd, CompletesWithRunning.CANNOT);
                String result = future.get();
                println("result is "+result);
                DebuggerObjectModel object_model = getObjectModel();
                object_model.invalidateAllLocalCaches();
                DebuggerObjectsProvider dbo = getDebuggerObjectsProvider();
                dbo.refresh();

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
        private DebuggerObjectModel getObjectModel() throws Exception {
            DebuggerObjectsPlugin objects =
                (DebuggerObjectsPlugin) state.getTool().getService(ObjectUpdateService.class);
            DebuggerModelService models = objects.modelService;
            DebuggerObjectModel model = models.getModels()
                .stream()
                .filter(DebuggerObjectModel.class::isInstance)
                .map(DebuggerObjectModel.class::cast)
                .findFirst()
                .orElse(null);
            if (model == null) {
                return null;
            }
            return model;
        }
        private DebuggerObjectsProvider getDebuggerObjectsProvider() throws Exception {
            DebuggerObjectsPlugin objects =
                (DebuggerObjectsPlugin) state.getTool().getService(ObjectUpdateService.class);
            return objects.getProvider(0);
        }
}

