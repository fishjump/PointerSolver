{-# LANGUAGE GADTs #-}

module PointerSolver.Solver.PcodeDeducer.UnknownOp where

import PointerSolver.Solver.PcodeDeducer.PcodeDeducer (Deducer)

data UnknownOp where
  UnknownOp :: UnknownOp

instance Deducer UnknownOp
