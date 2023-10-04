// Dumps the pcode into a nested json.
// @category PCode

import java.io.File;
import java.io.FileWriter;

import com.google.gson.GsonBuilder;

import ghidra.app.script.GhidraScript;
import v1.entity.Metadata;

public class GhidraMetaDumpHeadless extends GhidraScript {

    @Override
    public void run() throws Exception {
        var meta = new Metadata(currentProgram);

        var builder = new GsonBuilder();
        var gson = builder.create();
        var json = gson.toJson(meta);

        var base = System.getenv("OUT_DIR");
        var filePath = base + "/" + currentProgram.getName() + ".json";
        var file = new File(filePath);
        if (file.createNewFile()) {
            println("New file is created");
        } else {
            println("File already exists, will be overwritten");
        }

        var writer = new FileWriter(file, false);
        writer.write(json);
        writer.close();

        meta.functions.forEach(func -> {
            var fPath = base + "/" + currentProgram.getName() + "_" + func.name + ".dot";
            var f = new File(fPath);
            try {
                if (f.createNewFile()) {
                    println("New file is created");
                } else {
                    println("File already exists, will be overwritten");
                }

                var fw = new FileWriter(f, false);
                fw.write(func.dotGraph());
                fw.close();
            } catch (Exception e) {
            }

        });

    }
}