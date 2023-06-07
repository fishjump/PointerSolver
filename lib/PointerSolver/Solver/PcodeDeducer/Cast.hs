{-# LANGUAGE GADTs #-}

module PointerSolver.Solver.PcodeDeducer.Cast where

import PointerSolver.Solver.PcodeDeducer.PcodeDeducer (Deducer)

data Cast where
  Cast :: Cast

instance Deducer Cast
