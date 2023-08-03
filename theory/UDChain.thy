theory UDChain
    imports "Main"
            "HOL-Library.Finite_Map"
            "SolverTypes"
begin

type_synonym Context = "(PcodeId \<times> Varnode, PcodeId set) map"

function traceDefs' :: "PcodeId set \<Rightarrow> PcodeId set \<Rightarrow> Function \<Rightarrow> PcodeId \<Rightarrow> Varnode \<Rightarrow> PcodeId set" where
    "traceDefs' visited state func pcodeId varnode = (
        let visited' = insert pcodeId visited;
            isAssignment = (\<lambda>pId.
                let pcodeOpt = (pcodes func) pId
                in case pcodeOpt of
                    None \<Rightarrow> False |
                    Some x \<Rightarrow> (
                        case (pcodeOutput x) of
                            None \<Rightarrow> False |
                            Some _ \<Rightarrow> True));
            isOutputOf = (\<lambda>vnode pId.
                let pcodeOpt = (pcodes func) pId
                in case pcodeOpt of
                    None \<Rightarrow> False |
                    Some x \<Rightarrow> (
                        case (pcodeOutput x) of
                            None \<Rightarrow> False |
                            Some x' \<Rightarrow> x' = vnode));
            nextWithState = (\<lambda>s. 
                let pcodePredsOpt = (ControlFlowGraph.pcodes (cfg func)) pcodeId;
                    pcodePreds = (
                        case pcodePredsOpt of
                            None \<Rightarrow> empty | 
                            Some x \<Rightarrow> (PcodeControlFlow.preds x));
                    mappedPcodePreds = map 
                        (\<lambda>pcodeId' \<Rightarrow> traceDefs' visited' s func pcodeId' varnode) 
                        (list_of_set pcodePreds)
                in fold union mappedPcodePreds empty)
        in nextWithState state)" 
by auto

end