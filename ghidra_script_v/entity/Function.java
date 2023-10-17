package ghidra_script_v.entity;

import java.util.HashMap;
import java.util.Map;

import ghidra.program.model.block.BasicBlockModel;

public class Function {
    public String name;
    public String entry;
    public String exit;

    public Map<String, BasicBlock> basicblocks = new HashMap<>();
    public Map<String, Pcode> pcodes = new HashMap<>();
    public Map<String, Varnode> varnodes = new HashMap<>();
    // public Map<String, Symbol> symbols = new HashMap<>();

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEntry() {
        return entry;
    }

    public void setEntry(String entry) {
        this.entry = entry;
    }

    public String getExit() {
        return exit;
    }

    public void setExit(String exit) {
        this.exit = exit;
    }

    // ===== imples =====

    public Function(ghidra.program.model.listing.Function function) {
        this.function = function;
    }

    private ghidra.program.model.listing.Function function;

    public boolean stage1() throws Exception {
        name = function.getName();
        entry = function.getBody().getMinAddress().toString();
        exit = function.getBody().getMaxAddress().toString();

        // Dump basic block
        var basicBlockModel = new BasicBlockModel(function.getProgram());
        var basicBlocks = basicBlockModel.getCodeBlocks(null);

        for (var basicBlock : basicBlocks) {
            if (!function.getBody().contains(basicBlock)) {
                continue;
            }

            this.basicblocks.put(basicBlock.getFirstStartAddress().toString(), new BasicBlock(basicBlock));
        }

        for (var entry : this.basicblocks.entrySet()) {
            entry.getValue().stage1();
        }

        // Dump Pcode
        for (var basicBlock : basicBlocks) {
            var insts = function.getProgram().getListing().getInstructions(basicBlock, false);
            for (var inst : insts) {
                var pcodes = inst.getPcode(false);
                for (int i = 0; i < pcodes.length; i++) {
                    var pcode = new Pcode(inst.getAddress(), i, pcodes[i]);
                    this.pcodes.put(pcode.getId(), pcode);
                }
            }
        }

        return true;
    }
}
