{-# LANGUAGE GADTs #-}
{-# LANGUAGE InstanceSigs #-}

module PointerSolver.Solver.PcodeDeducer.CBranch where

import Data.Function ((&))
import PointerSolver.Solver.FSM.States (Event (ToBool, ToInt, ToPointer), transition)
import PointerSolver.Solver.PcodeDeducer.Helper (guardSize)
import PointerSolver.Solver.PcodeDeducer.PcodeDeducer (Deducer (deduceStage1, deduceStage2))
import PointerSolver.Solver.Context(Context, get, set)
import PointerSolver.Type.Pcode.Pcode (Pcode (Pcode))

data CBranch where
  CBranch :: CBranch

-- CBRAHCH input0 input1

instance Deducer CBranch where
  deduceStage1 :: CBranch -> Context -> Pcode -> Context
  deduceStage1 _ ctx (Pcode _ _ _ [input0, input1] Nothing) = ctx & set input0 input0Type' & set input1 input1Type'
    where
      input0Type = ctx & get input0
      input1Type = ctx & get input1
      input0Type' = transition ToInt input0Type
      input1Type' = transition ToBool input1Type

  deduceStage2 :: CBranch -> Context -> Pcode -> Context
  deduceStage2 _ ctx (Pcode _ _ _ [input0, _] Nothing) = ctx & set input0 input0Type'
    where
      input0Type = ctx & get input0
      input0Type' = ToPointer & guardSize' & (`transition` input0Type)
      guardSize' = guardSize 8 input0
