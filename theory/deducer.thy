theory deducer
    imports "Main"
            "HOL-Library.RBT"
            "SolverTypes"
            "StringLinorder"
begin

(* datatype IntLogicOp = IntLogicOp  *)

datatype IntLogicOp = Op1 | Op2
datatype Context = Ctx1 | Ctx2

datatype Pcode = Pcode nat nat nat "nat list" "nat option"

instantiation IntLogicOp :: deducer 
begin

fun deduceStage1 :: "IntLogicOp \<Rightarrow> Context \<Rightarrow> Pcode \<Rightarrow> Context" where
    "deduceStage1 _ ctx (Pcode _ _ _ [input0, input1] (Some output)) = ctx" | 
    "deduceStage1 _ ctx _ = ctx"

definition deduceStage2 :: "IntLogicOp \<Rightarrow> SolverContext \<Rightarrow> Pcode \<Rightarrow> SolverContext" where
    "deduceStage2 = default_deduce"

definition deduceStage3 :: "IntLogicOp \<Rightarrow> SolverContext \<Rightarrow> Pcode \<Rightarrow> SolverContext" where
    "deduceStage3 _ ctx _ = ctx"


end

end