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
// xxx
//
//@category RESim

import ghidra.app.script.GhidraScript; 
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.listing.*;
import ghidra.program.model.block.*;
import ghidra.program.model.address.*;
import ghidra.util.task.TaskMonitor;

import java.io.File;
import java.io.FileWriter;

import com.google.gson.*;
import com.google.gson.stream.JsonWriter;
import com.google.gson.JsonArray;



import java.util.*;

public class FindBlocks extends GhidraScript {
    /**
    * Create a json dump of the current program basic blocks, organized by function
    * and matching the syntax of similar files created by the findBlocks.py IDA Pro script. 
    */
	@Override
	protected void run() throws Exception {
        String outpath = currentProgram.getExecutablePath()+".blocks";
        File outputFile = new File(outpath);
        Gson gson = new GsonBuilder().setPrettyPrinting().create();

        JsonWriter jsonWriter = new JsonWriter(new FileWriter(outputFile));
        JsonObject theblocks = new JsonObject();

        BasicBlockModel bbm = new BasicBlockModel(currentProgram);
        FunctionManager fm = currentProgram.getFunctionManager();        
        for(Function f : fm.getFunctions(true)){
            Address min = f.getBody().getMinAddress();
            Address max = f.getBody().getMaxAddress();
            AddressSetView set = new AddressSet(min, max);
            CodeBlockIterator cbi = bbm.getCodeBlocksContaining(set, TaskMonitor.DUMMY);
            //println("name: "+f.getName());
            JsonObject function = new JsonObject();
            function.addProperty("name", min.getOffset());
            JsonArray funblocks = new JsonArray();
            for(CodeBlock cb : cbi){
                Address block_min = cb.getMinAddress();
                Address block_max = cb.getMaxAddress();
                //println("block: "+block_min+" - "+block_max);
                JsonObject block = new JsonObject();
                block.addProperty("start_ea", block_min.getOffset());
                block.addProperty("end_ea", block_min.getOffset());
                JsonArray succs_json = new JsonArray();
                CodeBlockReferenceIterator succs = cb.getDestinations(TaskMonitor.DUMMY);
                while(succs.hasNext()){
                    CodeBlockReference s = succs.next();
                    succs_json.add(s.getDestinationAddress().getOffset());
                }
                block.add("succs", succs_json); 
                funblocks.add(block);
            }
            function.add("blocks", funblocks);
            String fun_addr = String.valueOf(min.getOffset());
            theblocks.add(fun_addr, function);
        }
        gson.toJson(theblocks, jsonWriter);
        //jsonWriter.writeObject(theblocks);
        jsonWriter.close();
        println("Json of basic blocks written to "+outpath);
	}

}

