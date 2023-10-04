package entity;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import ghidra.program.model.pcode.HighFunction;

public class Function {
    public String name;
    public String entry;
    public String exit;

    public Map<String, BasicBlock> basicblocks = new HashMap<>();
    public Map<String, PCode> pcodes = new HashMap<>();
    public Set<String> varnodes = new HashSet<>();
    public Map<String, Symbol> symbols = new HashMap<>();

    public Function(HighFunction hF) {
        var func = hF.getFunction();

        // Basic metadata
        name = func.getName();
        entry = func.getBody().getMinAddress().toString();
        exit = func.getBody().getMaxAddress().toString();

        hF.getBasicBlocks().forEach(bb -> {
            var basicblock = new BasicBlock(bb);
            basicblocks.put(basicblock.id, basicblock);

            bb.getIterator().forEachRemaining((pOp) -> {
                var pcode = new PCode(pOp);
                pcodes.put(pcode.id, pcode);

                Arrays.asList(pOp.getInputs()).forEach(x -> {
                    varnodes.add(x.toString());
                });

                if (pOp.getOutput() != null) {
                    varnodes.add(pOp.getOutput().toString());
                }
            });
        });

        // Local Symbol
        hF.getLocalSymbolMap().getSymbols().forEachRemaining(hS -> {
            var symbol = new Symbol(hS);
            symbols.put(symbol.id, symbol);
        });

        // Global Symbol
        hF.getGlobalSymbolMap().getSymbols().forEachRemaining(hS -> {
            var symbol = new Symbol(hS);
            symbols.put(symbol.id, symbol);
        });

    }

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

    public Map<String, BasicBlock> getBasicblocks() {
        return basicblocks;
    }

    public void setBasicblocks(Map<String, BasicBlock> basicblocks) {
        this.basicblocks = basicblocks;
    }

    public Map<String, PCode> getPcodes() {
        return pcodes;
    }

    public void setPcodes(Map<String, PCode> pcodes) {
        this.pcodes = pcodes;
    }

    public Set<String> getVarnodes() {
        return varnodes;
    }

    public void setVarnodes(Set<String> varnodes) {
        this.varnodes = varnodes;
    }

    public Map<String, Symbol> getSymbols() {
        return symbols;
    }

    public void setSymbols(Map<String, Symbol> symbols) {
        this.symbols = symbols;
    }

}
