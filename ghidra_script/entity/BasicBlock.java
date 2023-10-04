package entity;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.pcode.PcodeBlockBasic;
import utils.Utils;

public class BasicBlock {
    public String id;
    public String entry;
    public String exit;

    public List<String> pcodes = new ArrayList<>();
    public List<String> preds = new ArrayList<String>();
    public List<String> succs = new ArrayList<String>();

    public BasicBlock(PcodeBlockBasic pcodeBB) {
        id = pcodeBB.getStart().toString();
        entry = pcodeBB.getStart().toString();
        exit = pcodeBB.getStop().toString();

        // add pcodes
        var it = pcodeBB.getIterator();
        while (it.hasNext()) {
            var pcodeOp = it.next();
            pcodes.add(Utils.PCodeId(pcodeOp));
        }

        for (int i = 0; i < pcodeBB.getInSize(); i++) {
            var in = pcodeBB.getIn(i);
            preds.add(in.getStart().toString());
        }

        for (int i = 0; i < pcodeBB.getOutSize(); i++) {
            var out = pcodeBB.getOut(i);
            succs.add(out.getStart().toString());
        }
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
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

    public List<String> getPcodes() {
        return pcodes;
    }

    public void setPcodes(List<String> pcodes) {
        this.pcodes = pcodes;
    }

    public List<String> getPreds() {
        return preds;
    }

    public void setPreds(List<String> preds) {
        this.preds = preds;
    }

    public List<String> getSuccs() {
        return succs;
    }

    public void setSuccs(List<String> succs) {
        this.succs = succs;
    }

}
