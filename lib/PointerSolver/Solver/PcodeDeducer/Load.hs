{-# LANGUAGE GADTs #-}
{-# LANGUAGE InstanceSigs #-}

module PointerSolver.Solver.PcodeDeducer.Load where

import Data.Function ((&))
import PointerSolver.Solver.FSM.States (Event (ToInt, ToPointer, ToPointerOfPointer), transition)
import qualified PointerSolver.Solver.FSM.States as Type
import PointerSolver.Solver.PcodeDeducer.Helper (guardSize, guardType)
import PointerSolver.Solver.PcodeDeducer.PcodeDeducer (Deducer (deduceStage1, deduceStage2, deduceStage3))
import PointerSolver.Solver.Context(Context, get, set)
import PointerSolver.Type.Pcode.Pcode (Pcode (Pcode))

data Load where
  Load :: Load

instance Deducer Load where
  deduceStage1 :: Load -> Context -> Pcode -> Context
  -- output = LOAD input0
  deduceStage1 _ ctx (Pcode _ _ _ [input0] (Just _)) = ctx & set input0 input0Type'
    where
      input0Type = ctx & get input0
      input0Type' = transition ToInt input0Type

  -- output = LOAD input0 input1
  deduceStage1 _ ctx (Pcode _ _ _ [input0, input1] (Just _)) = ctx & set input0 input0Type' & set input1 input1Type'
    where
      input0Type = ctx & get input0
      input1Type = ctx & get input1
      input0Type' = transition ToInt input0Type
      input1Type' = transition ToInt input1Type

  deduceStage2 :: Load -> Context -> Pcode -> Context
  -- output = LOAD input0
  deduceStage2 _ ctx (Pcode _ _ _ [input0] (Just _)) = ctx & set input0 input0Type'
    where
      input0Type = ctx & get input0
      input0Type' = ToPointer & guardSize' & (`transition` input0Type)
      guardSize' = guardSize 8 input0

  -- output = LOAD input0 input1
  deduceStage2 _ ctx (Pcode _ _ _ [input0, input1] (Just _)) = ctx & set input0 input0Type' & set input1 input1Type'
    where
      input0Type = ctx & get input0
      input1Type = ctx & get input1
      input0Type' = ToPointer & guardSize' input0 & (`transition` input0Type)
      input1Type' = ToPointer & guardSize' input1 & (`transition` input1Type)
      guardSize' = guardSize 8

  deduceStage3 :: Load -> Context -> Pcode -> Context
  -- output = LOAD input0
  deduceStage3 _ ctx (Pcode _ _ _ [input0] (Just output)) = ctx & set input0 input0Type'
    where
      outputType = ctx & get output
      input0Type = ctx & get input0
      input0Type' = ToPointerOfPointer & guardType' & guardSize' & (`transition` input0Type)
      guardType' = guardType [Type.Pointer] outputType
      guardSize' = guardSize 8 input0

  -- output = LOAD input0 input1
  deduceStage3 _ ctx (Pcode _ _ _ [input0, input1] (Just output)) = ctx & set input0 input0Type' & set input1 input1Type'
    where
      outputType = ctx & get output
      input0Type = ctx & get input0
      input1Type = ctx & get input1
      input0Type' = ToPointerOfPointer & guardType' & guardSize' input0 & (`transition` input0Type)
      input1Type' = ToPointerOfPointer & guardType' & guardSize' input1 & (`transition` input1Type)
      guardType' = guardType [Type.Pointer] outputType
      guardSize' = guardSize 8
