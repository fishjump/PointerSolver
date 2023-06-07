{-# LANGUAGE GADTs #-}
{-# LANGUAGE InstanceSigs #-}

module PointerSolver.Solver.PcodeDeducer.Store where

import Data.Function ((&))
import PointerSolver.Solver.FSM.States (Event (ToInt, ToPointer, ToPointerOfPointer), transition)
import qualified PointerSolver.Solver.FSM.States as Type
import PointerSolver.Solver.PcodeDeducer.Helper (guardSize, guardType)
import PointerSolver.Solver.PcodeDeducer.PcodeDeducer (Deducer (deduceStage1, deduceStage2, deduceStage3))
import PointerSolver.Solver.Context(Context, get, set)
import PointerSolver.Type.Pcode.Pcode (Pcode (Pcode))

data Store where
  Store :: Store

instance Deducer Store where
  deduceStage1 :: Store -> Context -> Pcode -> Context
  -- STORE input0 input1
  deduceStage1 _ ctx (Pcode _ _ _ [input0, input1] Nothing) = ctx & set input0 input0Type' & set input1 input1Type'
    where
      input0Type = ctx & get input0
      input1Type = ctx & get input1
      input0Type' = transition ToInt input0Type
      input1Type' = transition ToInt input1Type

  -- STORE input0 input1 input2
  deduceStage1 _ ctx (Pcode _ _ _ [input0, input1, input2] Nothing) = ctx & set input0 input0Type' & set input1 input1Type' & set input2 input2Type'
    where
      input0Type = ctx & get input0
      input1Type = ctx & get input1
      input2Type = ctx & get input2
      input0Type' = transition ToInt input0Type
      input1Type' = transition ToInt input1Type
      input2Type' = transition ToInt input2Type

  deduceStage2 :: Store -> Context -> Pcode -> Context
  -- STORE input0 input1
  deduceStage2 _ ctx (Pcode _ _ _ [input0, _] Nothing) = ctx & set input0 input0Type'
    where
      input0Type = ctx & get input0
      input0Type' = ToPointer & guardSize' & (`transition` input0Type)
      guardSize' = guardSize 8 input0

  -- STORE input0 input1 input2
  deduceStage2 _ ctx (Pcode _ _ _ [input0, input1, _] Nothing) = ctx & set input0 input0Type' & set input1 input1Type'
    where
      input0Type = ctx & get input0
      input1Type = ctx & get input1
      input0Type' = ToPointer & guardSize' input0 & (`transition` input0Type)
      input1Type' = ToPointer & guardSize' input1 & (`transition` input1Type)
      guardSize' = guardSize 8

  deduceStage3 :: Store -> Context -> Pcode -> Context
  deduceStage3 _ ctx (Pcode _ _ _ [input0, input1] Nothing) = ctx & set input0 input0Type'
    where
      input0Type = ctx & get input0
      input1Type = ctx & get input1
      input0Type' = ToPointerOfPointer & guardType' & guardSize' & (`transition` input0Type)
      guardType' = guardType [Type.Pointer] input1Type
      guardSize' = guardSize 8 input0

  -- STORE input0 input1 input2
  deduceStage3 _ ctx (Pcode _ _ _ [input0, input1, input2] Nothing) = ctx & set input0 input0Type' & set input1 input1Type'
    where
      input0Type = ctx & get input0
      input1Type = ctx & get input1
      input2Type = ctx & get input2
      input0Type' = ToPointerOfPointer & guardType' & guardSize' input0 & (`transition` input0Type)
      input1Type' = ToPointerOfPointer & guardType' & guardSize' input1 & (`transition` input1Type)
      guardType' = guardType [Type.Pointer] input2Type
      guardSize' = guardSize 8
