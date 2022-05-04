/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// Displays a table of RESim watch marks.


// @category Debugger 

import java.util.Iterator;
import java.util.function.Consumer;
import java.util.List;
import java.util.ArrayList;

import org.apache.commons.collections4.IteratorUtils;

import ghidra.app.script.GhidraScript;
import ghidra.app.tablechooser.*;
import ghidra.program.model.address.Address;
import ghidra.util.task.TaskMonitor;
//import ghidra.app.plugin.core.debug.gui.watchmarks.DebuggerWatchMarksProvider;
//import ghidra.app.plugin.core.debug.gui.watchmarks.WatchMarksRow;
import resim.watchmarks.WatchMarksRow;
import resim.watchmarks.DebuggerWatchMarksProvider;
import ghidra.app.plugin.core.debug.gui.objects.DebuggerObjectsPlugin;
import ghidra.app.plugin.core.debug.gui.objects.ObjectUpdateService;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.DebuggerModelService;

public class WatchMarks extends GhidraScript {

	@Override
	protected void run() throws Exception {
                /*
                List<String> data = new ArrayList<>();
                data.add("some line");
                data.add("some other line");
                String val = askChoice("Watch Marks", "pick a mark", data, null);
                println("got "+val);
                */
                 println("here goes");
                 DebuggerWatchMarksProvider dmp = (DebuggerWatchMarksProvider) state.getTool().getComponentProvider("WatchMarks");
                 if(dmp == null){
                     println("is potato");
                     return;
                 }
                 dmp.refresh();
                 /*
                 Address a1 = currentAddress.getNewAddress(0x1111);
                 WatchMarksRow wmr = new WatchMarksRow(dmp, 1, "first message", a1);
                 dmp.add(wmr);
                 WatchMarksRow wmr2 = new WatchMarksRow(dmp, 2, "next message", a1);
                 dmp.add(wmr2);
                 */
                 
        }
}
