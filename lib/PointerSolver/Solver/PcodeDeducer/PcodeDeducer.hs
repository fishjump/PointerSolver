module PointerSolver.Solver.PcodeDeducer.PcodeDeducer where

import PointerSolver.Solver.Context (Context)
import PointerSolver.Type.Pcode.Pcode (Pcode)

class Deducer a where
  deduceStage1 :: a -> Context -> Pcode -> Context
  deduceStage1 _ ctx _ = ctx

  deduceStage2 :: a -> Context -> Pcode -> Context
  deduceStage2 _ ctx _ = ctx

  deduceStage3 :: a -> Context -> Pcode -> Context
  deduceStage3 _ ctx _ = ctx
