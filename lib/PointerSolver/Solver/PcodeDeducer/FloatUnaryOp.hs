{-# LANGUAGE GADTs #-}
{-# LANGUAGE InstanceSigs #-}

module PointerSolver.Solver.PcodeDeducer.FloatUnaryOp where

import Data.Function ((&))
import PointerSolver.Solver.Context (Context, get, set)
import PointerSolver.Solver.FSM.States (Event (ToFloat), transition)
import PointerSolver.Solver.PcodeDeducer.PcodeDeducer (Deducer (deduceStage1))
import PointerSolver.Type.Pcode.Pcode (Pcode (Pcode))

data FloatUnaryOp where
  FloatUnaryOp :: FloatUnaryOp

instance Deducer FloatUnaryOp where
  deduceStage1 :: FloatUnaryOp -> Context -> Pcode -> Context
  deduceStage1 _ ctx (Pcode _ _ _ [input0] (Just output)) = ctx & set input0 input0Type' & set output outputType'
    where
      input0Type = ctx & get input0
      outputType = ctx & get output
      input0Type' = transition ToFloat input0Type
      outputType' = transition ToFloat outputType
