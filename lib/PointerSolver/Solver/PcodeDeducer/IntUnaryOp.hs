{-# LANGUAGE GADTs #-}
{-# LANGUAGE InstanceSigs #-}

module PointerSolver.Solver.PcodeDeducer.IntUnaryOp where

import Data.Function ((&))
import PointerSolver.Solver.Context (Context, get, set)
import PointerSolver.Solver.FSM.States (Event (ToInt, ToPointer, ToPointerOfPointer), transition)
import qualified PointerSolver.Solver.FSM.States as Type
import PointerSolver.Solver.PcodeDeducer.Helper (guardSize, guardTypeAny)
import PointerSolver.Solver.PcodeDeducer.PcodeDeducer (Deducer (deduceStage1, deduceStage2, deduceStage3))
import PointerSolver.Type.Pcode.Pcode (Pcode (Pcode))

data IntUnaryOp where
  IntUnaryOp :: IntUnaryOp

instance Deducer IntUnaryOp where
  deduceStage1 :: IntUnaryOp -> Context -> Pcode -> Context
  deduceStage1 _ ctx (Pcode _ _ _ [input0] (Just output)) = ctx & set input0 input0Type' & set output outputType'
    where
      input0Type = ctx & get input0
      outputType = ctx & get output
      input0Type' = transition ToInt input0Type
      outputType' = transition ToInt outputType

  deduceStage2 :: IntUnaryOp -> Context -> Pcode -> Context
  deduceStage2 _ ctx (Pcode _ _ _ [input0] (Just output)) = ctx & set input0 input0Type' & set output outputType'
    where
      input0Type = ctx & get input0
      outputType = ctx & get output
      input0Type' = ToPointer & guardType' & guardSize' input0 & (`transition` input0Type)
      outputType' = ToPointer & guardType' & guardSize' output & (`transition` input0Type)
      guardType' = guardTypeAny [Type.Pointer] [input0Type, outputType]
      guardSize' = guardSize 8

  deduceStage3 :: IntUnaryOp -> Context -> Pcode -> Context
  deduceStage3 _ ctx (Pcode _ _ _ [input0] (Just output)) = ctx & set input0 input0Type' & set output outputType'
    where
      input0Type = ctx & get input0
      outputType = ctx & get output
      input0Type' = ToPointerOfPointer & guardType' & guardSize' input0 & (`transition` input0Type)
      outputType' = ToPointerOfPointer & guardType' & guardSize' output & (`transition` input0Type)
      guardType' = guardTypeAny [Type.PointerOfPointer] [input0Type, outputType]
      guardSize' = guardSize 8
