theory UDChain
    imports "Main"
            "HOL-Library.RBT"
            "SolverTypes"
            "StringLinorder"
begin

type_synonym Context = "(PcodeId \<times> Varnode, PcodeId set) rbt"

fun rbt_of_list :: "('a::linorder \<times> 'b) list \<Rightarrow> ('a, 'b) rbt" where
  "rbt_of_list [] = RBT.empty" |
  "rbt_of_list ((k, v) # xs) = RBT.insert k v (rbt_of_list xs)"

definition my_rbt :: "Context" where
  "my_rbt = rbt_of_list [((''123'', ''123A''), empty)]"

value "the (RBT.lookup my_rbt (''123'', ''123A''))"

function defs' :: "PcodeId set => PcodeId set => Function => PcodeId \<Rightarrow> Varnode \<Rightarrow> PcodeId set" where
    "defs' visited state func pcodeId varnode = (
        let visited' = insert pcodeId visited;
            state' = insert pcodeId state;
            isAssignment = (\<lambda>pId.
                    let pcodeOpt = RBT.lookup (pcodes func) pId
                    in case pcodeOpt of
                        None \<Rightarrow> False |
                        Some x \<Rightarrow> (
                            case (pcodeOutput x) of
                                None \<Rightarrow> False |
                                Some _ \<Rightarrow> True));
            isOutputOf = (\<lambda>vnode pId.
                    let pcodeOpt = RBT.lookup (pcodes func) pId
                    in case pcodeOpt of
                        None \<Rightarrow> False |
                        Some x \<Rightarrow> (
                            case (pcodeOutput x) of
                                None \<Rightarrow> False |
                                Some x' \<Rightarrow> x' = vnode));
            nextWithState = (\<lambda>s :: PcodeId set. 
                    let pcodePredsOpt = RBT.lookup (ControlFlowGraph.pcodes (cfg func)) pcodeId;
                        pcodePreds = (
                            case pcodePredsOpt of
                                None \<Rightarrow> empty | 
                                Some x \<Rightarrow> (PcodeControlFlow.preds x));
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
            pcodes = Function.pcodes function;
            zipPcode = (\<lambda>p. map (\<lambda>x. (Pcode.id p, x)) (Pcode.inputs p));
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