package ghidra_script_v.entity;

import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.PcodeOp;

public class Pcode {
    public String operation;
    public String parent;

    private String address;
    private int seqnum;

    public String getId() {
        return String.format("%s:%d", address, seqnum);
    }

    public String toString() {
        return getId();
    }

    // ===== imples =====

    public Pcode(Address address, int seqnum, PcodeOp pcodeOp) {
        this.address = address.toString();
        this.seqnum = seqnum;
        this.pcodeOp = pcodeOp;
    }

    private PcodeOp pcodeOp;
}
