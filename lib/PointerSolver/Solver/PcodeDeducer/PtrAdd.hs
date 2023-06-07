{-# LANGUAGE GADTs #-}
{-# LANGUAGE InstanceSigs #-}

module PointerSolver.Solver.PcodeDeducer.PtrAdd where

import Data.Function ((&))
import PointerSolver.Solver.FSM.States (Event (ToInt, ToPointer), transition)
import PointerSolver.Solver.PcodeDeducer.Helper (guardSize)
import PointerSolver.Solver.PcodeDeducer.PcodeDeducer (Deducer (deduceStage1, deduceStage2))
import PointerSolver.Solver.Context(Context, get, set)
import PointerSolver.Type.Pcode.Pcode (Pcode (Pcode))

data PtrAdd where
  PtrAdd :: PtrAdd

-- output = PTRADD input0 input1 input2

instance Deducer PtrAdd where
  deduceStage1 :: PtrAdd -> Context -> Pcode -> Context
  deduceStage1 _ ctx (Pcode _ _ _ [input0, input1, input2] (Just output)) = ctx & set input0 input0Type' & set input1 input1Type' & set input2 input2Type' & set output outputType'
    where
      input0Type = ctx & get input0
      input1Type = ctx & get input1
      input2Type = ctx & get input2
      outputType = ctx & get output
      input0Type' = transition ToInt input0Type
      input1Type' = transition ToInt input1Type
      input2Type' = transition ToInt input2Type
      outputType' = transition ToInt outputType

  deduceStage2 :: PtrAdd -> Context -> Pcode -> Context
  deduceStage2 _ ctx (Pcode _ _ _ [input0, _, _] (Just output)) = ctx & set input0 input0Type' & set output outputType'
    where
      input0Type = ctx & get input0
      outputType = ctx & get output
      input0Type' = ToPointer & guardSize' input0 & (`transition` input0Type)
      outputType' = ToPointer & guardSize' output & (`transition` outputType)
      guardSize' = guardSize 8