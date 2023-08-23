theory Solver
    imports "Main"
            "HOL-Library.RBT"
            "SolverTypes"
            "StringLinorder"
begin

type_synonym Context = "(Varnode, Type) rbt"
type_synonym UDChainContext = "(PcodeId \<times> Varnode, PcodeId set) rbt"

function solvePcode :: "(PcodeOp \<Rightarrow> Context \<Rightarrow> Pcode \<Rightarrow> Context) \<Rightarrow> Context \<Rightarrow> Function \<Rightarrow> PcodeId set \<Rightarrow> PcodeId \<Rightarrow> UDChainContext \<Rightarrow> (PcodeId set \<times> Context)" where
    "solvePcode deducer ctx func visited pcodeId udChainCtx = (visited, ctx)"
by auto

end