package ghidra_script_v.entity;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.program.model.listing.Program;

public class Metadata {
    public List<Function> functions = new ArrayList<>();

    public List<Function> getFunctions() {
        return functions;
    }

    public void setFunctions(List<Function> functions) {
        this.functions = functions;
    }

    // ===== imples =====

    public Metadata(Program program) {
        this.program = program;
    }

    private Program program;

    public void stage1() throws Exception {
        var dIf = new DecompInterface();
        var options = new DecompileOptions();
        dIf.setOptions(options);
        dIf.openProgram(program);

        for (var func : program.getFunctionManager().getFunctions(false)) {
            if (func.isThunk()) {
                continue;
            }

            functions.add(new Function(func));
        }

        for (var func : functions) {
            func.stage1();
        }
    }
}
