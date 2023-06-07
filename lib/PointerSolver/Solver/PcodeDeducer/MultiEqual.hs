{-# LANGUAGE GADTs #-}

module PointerSolver.Solver.PcodeDeducer.MultiEqual where

import PointerSolver.Solver.PcodeDeducer.PcodeDeducer (Deducer)

data MultiEqual where
  MultiEqual :: MultiEqual

instance Deducer MultiEqual
