{-# LANGUAGE GADTs #-}
{-# LANGUAGE InstanceSigs #-}

module PointerSolver.Solver.PcodeDeducer.BoolBinOp where

import Data.Function ((&))
import PointerSolver.Solver.Context (Context, get, set)
import PointerSolver.Solver.FSM.States (Event (ToBool), transition)
import PointerSolver.Solver.PcodeDeducer.PcodeDeducer (Deducer (deduceStage1))
import PointerSolver.Type.Pcode.Pcode (Pcode (Pcode))

data BoolBinOp where
  BoolBinOp :: BoolBinOp

instance Deducer BoolBinOp where
  deduceStage1 :: BoolBinOp -> Context -> Pcode -> Context
  deduceStage1 _ ctx (Pcode _ _ _ [input0, input1] (Just output)) = ctx & set input0 input0Type' & set input1 input1Type' & set output outputType'
    where
      input0Type = ctx & get input0
      input1Type = ctx & get input1
      outputType = ctx & get output
      input0Type' = transition ToBool input0Type
      input1Type' = transition ToBool input1Type
      outputType' = transition ToBool outputType
