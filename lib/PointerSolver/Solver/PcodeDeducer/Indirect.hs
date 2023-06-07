{-# LANGUAGE GADTs #-}

module PointerSolver.Solver.PcodeDeducer.Indirect where

import PointerSolver.Solver.PcodeDeducer.PcodeDeducer (Deducer)

data Indirect where
  Indirect :: Indirect

instance Deducer Indirect
