theory Solver
    imports "Main"
            "deducer"
            "HOL-Library.RBT"
            "SolverTypes"
            "StringLinorder"
begin

function stage1Deducer :: "PcodeOp \<Rightarrow> SolverContext \<Rightarrow> Pcode \<Rightarrow> SolverContext" where
    "stage1Deducer INT_EQUAL = deduceStage1 IntLogicOp" |
    "stage1Deducer _ = deduceStage1 IntLogicOp"
by auto

function solvePcode :: "(PcodeOp \<Rightarrow> SolverContext \<Rightarrow> Pcode \<Rightarrow> SolverContext) \<Rightarrow> SolverContext \<Rightarrow> Function \<Rightarrow> PcodeId set \<Rightarrow> PcodeId \<Rightarrow> UDChainContext \<Rightarrow> (PcodeId set \<times> SolverContext)" where
    "solvePcode deducer ctx func visited pcodeId udChainCtx = (visited, ctx)"
by auto

function solveStage1 :: "SolverContext \<Rightarrow> Function \<Rightarrow> PcodeId set \<Rightarrow> PcodeId \<Rightarrow> UDChainContext \<Rightarrow> SolverContext" where
    "solveStage1 ctx func visited pcodeId udChainCtx = snd (solvePcode stage1Deducer ctx func visited pcodeId udChainCtx)"
by auto

end