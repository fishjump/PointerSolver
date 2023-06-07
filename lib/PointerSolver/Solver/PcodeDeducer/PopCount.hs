{-# LANGUAGE GADTs #-}

module PointerSolver.Solver.PcodeDeducer.PopCount where

import PointerSolver.Solver.PcodeDeducer.PcodeDeducer (Deducer)

data PopCount where
  PopCount :: PopCount

instance Deducer PopCount
