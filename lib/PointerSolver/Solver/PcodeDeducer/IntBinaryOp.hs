{-# LANGUAGE GADTs #-}
{-# LANGUAGE InstanceSigs #-}

module PointerSolver.Solver.PcodeDeducer.IntBinaryOp where

import Data.Function ((&))
import PointerSolver.Solver.Context (Context, get, set)
import PointerSolver.Solver.FSM.States (Event (ToInt, ToPointer, ToPointerOfPointer), transition)
import qualified PointerSolver.Solver.FSM.States as Type
import PointerSolver.Solver.PcodeDeducer.Helper (guardSize, guardTypeAny)
import PointerSolver.Solver.PcodeDeducer.PcodeDeducer (Deducer (deduceStage1, deduceStage2, deduceStage3))
import PointerSolver.Type.Pcode.Pcode (Pcode (Pcode))

data IntBinaryOp where
  IntBinaryOp :: IntBinaryOp

instance Deducer IntBinaryOp where
  deduceStage1 :: IntBinaryOp -> Context -> Pcode -> Context
  deduceStage1 _ ctx (Pcode _ _ _ [input0, input1] (Just output)) = ctx & set input0 input0Type' & set input1 input1Type' & set output outputType'
    where
      input0Type = ctx & get input0
      input1Type = ctx & get input1
      outputType = ctx & get output
      input0Type' = transition ToInt input0Type
      input1Type' = transition ToInt input1Type
      outputType' = transition ToInt outputType

  deduceStage2 :: IntBinaryOp -> Context -> Pcode -> Context
  deduceStage2 _ ctx (Pcode _ _ _ [input0, input1] (Just output)) = ctx & set input0 input0Type' & set input0 input1Type' & set output outputType'
    where
      input0Type = ctx & get input0
      input1Type = ctx & get input1
      outputType = ctx & get output
      input0Type' = ToPointer & guardType' & guardSize' input0 & (`transition` input0Type)
      input1Type' = ToPointer & guardType' & guardSize' input1 & (`transition` input1Type)
      outputType' = ToPointer & guardType' & guardSize' output & (`transition` outputType)
      guardType' = guardTypeAny [Type.Pointer] [input0Type, input1Type, outputType]
      guardSize' = guardSize 8

  deduceStage3 :: IntBinaryOp -> Context -> Pcode -> Context
  deduceStage3 _ ctx (Pcode _ _ _ [input0, input1] (Just output)) = ctx & set input0 input0Type' & set input0 input1Type' & set output outputType'
    where
      input0Type = ctx & get input0
      input1Type = ctx & get input1
      outputType = ctx & get output
      input0Type' = ToPointerOfPointer & guardType' & guardSize' input0 & (`transition` input0Type)
      input1Type' = ToPointerOfPointer & guardType' & guardSize' input1 & (`transition` input1Type)
      outputType' = ToPointerOfPointer & guardType' & guardSize' output & (`transition` outputType)
      guardType' = guardTypeAny [Type.PointerOfPointer] [input0Type, input1Type, outputType]
      guardSize' = guardSize 8
