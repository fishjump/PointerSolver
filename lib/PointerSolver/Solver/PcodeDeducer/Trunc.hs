{-# LANGUAGE GADTs #-}
{-# LANGUAGE InstanceSigs #-}

module PointerSolver.Solver.PcodeDeducer.Trunc where

import Data.Function ((&))
import PointerSolver.Solver.FSM.States (Event (ToFloat, ToInt), transition)
import PointerSolver.Solver.PcodeDeducer.PcodeDeducer (Deducer (deduceStage1))
import PointerSolver.Solver.Context(Context, get, set)
import PointerSolver.Type.Pcode.Pcode (Pcode (Pcode))

data Trunc where
  Trunc :: Trunc

-- output = TRUNC input0

instance Deducer Trunc where
  deduceStage1 :: Trunc -> Context -> Pcode -> Context
  deduceStage1 _ ctx (Pcode _ _ _ [input0] (Just output)) = ctx & set input0 input0Type' & set output outputType'
    where
      input0Type = ctx & get input0
      outputType = ctx & get output
      input0Type' = transition ToFloat input0Type
      outputType' = transition ToInt outputType
