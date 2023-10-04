package entity;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.collections4.IteratorUtils;

import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import utils.PCodeOpNameCvt;
import utils.Utils;

public class PCode {
    public String id;
    public String operation;
    public String parent;

    public List<String> inputs = new ArrayList<>();
    public String output;

    public List<String> preds = new ArrayList<String>();
    public List<String> succs = new ArrayList<String>();

    public PCode(PcodeOp pcodeOp) {
        id = Utils.PCodeId(pcodeOp);
        operation = PCodeOpNameCvt.get(pcodeOp.getOpcode());
        parent = pcodeOp.getParent().getStart().toString();

        for (var input : pcodeOp.getInputs()) {
            inputs.add(input.toString());
        }

        if (pcodeOp.getOutput() != null) {
            output = pcodeOp.getOutput().toString();
        }

        var currentBB = pcodeOp.getParent();
        var inBlkPcodes = IteratorUtils.toList(currentBB.getIterator());

        // if current pcode is the first one, i.e., predesessor is in another BB
        if (pcodeOp.getSeqnum().getOrder() == 0) {
            // find the pred bb and add the last
            for (int i = 0; i < currentBB.getInSize(); i++) {
                var predBB = (PcodeBlockBasic) currentBB.getIn(i);
                var inBlkPcodesPred = IteratorUtils.toList(predBB.getIterator());
                if (inBlkPcodesPred.size() > 0) {
                    var last = inBlkPcodesPred.get(inBlkPcodesPred.size() - 1);
                    preds.add(Utils.PCodeId(last));
                }
            }
        } else {
            preds.add(Utils.PCodeId(currentBB.getStart().toString(), pcodeOp.getSeqnum().getOrder() - 1));
        }

        // if current pcode is the last one, i.e., successor is in another BB
        if ((pcodeOp.getSeqnum().getOrder() + 1) == inBlkPcodes.size()) {
            // find the succ bb and add the first
            for (int i = 0; i < currentBB.getOutSize(); i++) {
                var succBB = (PcodeBlockBasic) currentBB.getOut(i);
                var inBlkPcodesSucc = IteratorUtils.toList(succBB.getIterator());
                if (inBlkPcodesSucc.size() > 0) {
                    var first = inBlkPcodesSucc.get(0);
                    succs.add(Utils.PCodeId(first));
                }
            }
        } else {
            succs.add(Utils.PCodeId(currentBB.getStart().toString(), pcodeOp.getSeqnum().getOrder() + 1));
        }
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getOperation() {
        return operation;
    }

    public void setOperation(String operation) {
        this.operation = operation;
    }

    public String getParent() {
        return parent;
    }

    public void setParent(String parent) {
        this.parent = parent;
    }

    public List<String> getInputs() {
        return inputs;
    }

    public void setInputs(List<String> inputs) {
        this.inputs = inputs;
    }

    public String getOutput() {
        return output;
    }

    public void setOutput(String output) {
        this.output = output;
    }
}
