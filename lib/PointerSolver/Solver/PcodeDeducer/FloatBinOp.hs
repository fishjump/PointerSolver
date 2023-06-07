{-# LANGUAGE GADTs #-}
{-# LANGUAGE InstanceSigs #-}

module PointerSolver.Solver.PcodeDeducer.FloatBinOp where

import Data.Function ((&))
import PointerSolver.Solver.Context (Context, get, set)
import PointerSolver.Solver.FSM.States (Event (ToFloat), transition)
import PointerSolver.Solver.PcodeDeducer.PcodeDeducer (Deducer (deduceStage1))
import PointerSolver.Type.Pcode.Pcode (Pcode (Pcode))

data FloatBinOp where
  FloatBinOp :: FloatBinOp

instance Deducer FloatBinOp where
  deduceStage1 :: FloatBinOp -> Context -> Pcode -> Context
  deduceStage1 _ ctx (Pcode _ _ _ [input0, input1] (Just output)) = ctx & set input0 input0Type' & set input1 input1Type' & set output outputType'
    where
      input0Type = ctx & get input0
      input1Type = ctx & get input1
      outputType = ctx & get output
      input0Type' = transition ToFloat input0Type
      input1Type' = transition ToFloat input1Type
      outputType' = transition ToFloat outputType
