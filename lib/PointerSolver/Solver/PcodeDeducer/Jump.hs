{-# LANGUAGE GADTs #-}
{-# LANGUAGE InstanceSigs #-}

module PointerSolver.Solver.PcodeDeducer.Jump where

import Data.Function ((&))
import PointerSolver.Solver.Context (Context, get, set)
import PointerSolver.Solver.FSM.States (Event (ToInt, ToPointer), transition)
import PointerSolver.Solver.PcodeDeducer.Helper (guardSize)
import PointerSolver.Solver.PcodeDeducer.PcodeDeducer (Deducer (deduceStage1, deduceStage2))
import PointerSolver.Type.Pcode.Pcode (Pcode (Pcode))

data Jump where
  Jump :: Jump

-- BRANCH input0
-- BRANCHIND input0
-- CALL input0
-- CALLIND input0
-- RETURN input0

instance Deducer Jump where
  deduceStage1 :: Jump -> Context -> Pcode -> Context
  deduceStage1 _ ctx (Pcode _ _ _ [input0] Nothing) = ctx & set input0 input0Type'
    where
      input0Type = ctx & get input0
      input0Type' = transition ToInt input0Type
  deduceStage1 _ ctx _ = ctx

  deduceStage2 :: Jump -> Context -> Pcode -> Context
  deduceStage2 _ ctx (Pcode _ _ _ [input0] Nothing) = ctx & set input0 input0Type'
    where
      input0Type = ctx & get input0
      input0Type' = ToPointer & guardSize' & (`transition` input0Type)
      guardSize' = guardSize 8 input0
  deduceStage2 _ ctx _ = ctx
