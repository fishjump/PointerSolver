theory UDChain
    imports "Main"
            "HOL-Library.RBT"
            "SolverTypes"
            "StringLinorder"
begin

type_synonym Context = "(PcodeId \<times> Varnode, PcodeId set) rbt"


function defs' :: "PcodeId set => PcodeId set => Function => PcodeId \<Rightarrow> Varnode \<Rightarrow> PcodeId set" where
    "defs' visited state func pcodeId varnode = (
        let visited' = insert pcodeId visited;
            state' = insert pcodeId state;
            isAssignment = (\<lambda>pId.
                    let pcodeOpt = RBT.lookup (Function_Pcodes func) pId
                    in case pcodeOpt of
                        None \<Rightarrow> False |
                        Some x \<Rightarrow> (
                            case (Pcode_Output x) of
                                None \<Rightarrow> False |
                                Some _ \<Rightarrow> True));
            isOutputOf = (\<lambda>vnode pId.
                    let pcodeOpt = RBT.lookup (Function_Pcodes func) pId
                    in case pcodeOpt of
                        None \<Rightarrow> False |
                        Some x \<Rightarrow> (
                            case (Pcode_Output x) of
                                None \<Rightarrow> False |
                                Some x' \<Rightarrow> x' = vnode));
            nextWithState = (\<lambda>s :: PcodeId set. 
                    let pcodePredsOpt = RBT.lookup (ControlFlowGraph_Pcodes (Function_Cfg func)) pcodeId;
                        pcodePreds = (
                            case pcodePredsOpt of
                                None \<Rightarrow> empty | 
                                Some x \<Rightarrow> (PcodeControlFlow_Preds x));
                        mappedPcodePreds = map 
                            (\<lambda>pcodeId' \<Rightarrow> defs' visited' s func pcodeId' varnode) 
                            (sorted_list_of_set pcodePreds)
                    in s)
        in (if pcodeId \<in> visited then
                state
            else if isAssignment pcodeId \<and> isOutputOf varnode pcodeId then 
                nextWithState state' 
            else state))"
by auto

function defs :: "Context \<Rightarrow> Function \<Rightarrow> PcodeId \<Rightarrow> Varnode \<Rightarrow> (Context \<times> PcodeId set)" where
    "defs ctx func pcodeId varnode = (
        let containsKey = (case RBT.lookup ctx (pcodeId, varnode) of 
                            Some _ \<Rightarrow> True | None \<Rightarrow> False);
            defSet = (case RBT.lookup ctx (pcodeId, varnode) of
                        Some x \<Rightarrow> x | None \<Rightarrow> empty);
            defSet' = defs' empty empty func pcodeId varnode;
            ctx' = RBT.insert (pcodeId, varnode) defSet' ctx
        in (if containsKey then
                (ctx, defSet)
            else
                (ctx', defSet')))"
by auto

function udChain :: "Function \<Rightarrow> Context" where
    "udChain function = (
        let ctx = RBT.empty;
            pcodes = Function_Pcodes function;
            zipPcode = (\<lambda>p. map (\<lambda>x. (Pcode_Id p, x)) (Pcode_Inputs p));
            targets = map (\<lambda>pId. zipPcode (the (RBT.lookup pcodes pId))) (RBT.keys pcodes);
            targets' = concat targets
        in foldr (\<lambda>(pId, varnode). 
                let result = defs ctx function pId varnode;
                    ctx' = fst result
                in RBT.union ctx'
            ) targets' ctx
    )"
by auto

end