{-# LANGUAGE GADTs #-}
{-# LANGUAGE InstanceSigs #-}

module PointerSolver.Solver.PcodeDeducer.Copy where

import Data.Function ((&))
import PointerSolver.Solver.Context (Context, get, set)
import PointerSolver.Solver.FSM.States (toSome, transition)
import qualified PointerSolver.Solver.FSM.States as Type
import PointerSolver.Solver.PcodeDeducer.Helper (guardSize, guardType)
import PointerSolver.Solver.PcodeDeducer.PcodeDeducer (Deducer (deduceStage1, deduceStage2, deduceStage3))
import PointerSolver.Type.Pcode.Pcode (Pcode (Pcode))

data Copy where
  Copy :: Copy

-- output = COPY input0

instance Deducer Copy where
  deduceStage1 :: Copy -> Context -> Pcode -> Context
  deduceStage1 _ ctx (Pcode _ _ _ [input0] (Just output)) = ctx & set input0 input0Type' & set output outputType'
    where
      input0Type = ctx & get input0
      outputType = ctx & get output
      input0Type' = outputType & toSome & guardType' outputType & (`transition` input0Type)
      outputType' = input0Type & toSome & guardType' input0Type & (`transition` outputType)
      guardType' = guardType [Type.Int, Type.Bool, Type.Float]

  deduceStage2 :: Copy -> Context -> Pcode -> Context
  deduceStage2 _ ctx (Pcode _ _ _ [input0] (Just output)) = ctx & set input0 input0Type' & set output outputType'
    where
      input0Type = ctx & get input0
      outputType = ctx & get output
      input0Type' = outputType & toSome & guardType' outputType & guardSize' input0 & (`transition` input0Type)
      outputType' = input0Type & toSome & guardType' input0Type & guardSize' output & (`transition` outputType)
      guardType' = guardType [Type.Pointer]
      guardSize' = guardSize 8

  deduceStage3 :: Copy -> Context -> Pcode -> Context
  deduceStage3 _ ctx (Pcode _ _ _ [input0] (Just output)) = ctx & set input0 input0Type' & set output outputType'
    where
      input0Type = ctx & get input0
      outputType = ctx & get output
      input0Type' = outputType & toSome & guardType' outputType & guardSize' input0 & (`transition` input0Type)
      outputType' = input0Type & toSome & guardType' input0Type & guardSize' output & (`transition` outputType)
      guardType' = guardType [Type.PointerOfPointer]
      guardSize' = guardSize 8
