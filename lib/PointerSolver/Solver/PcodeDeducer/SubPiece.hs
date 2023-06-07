{-# LANGUAGE GADTs #-}

module PointerSolver.Solver.PcodeDeducer.SubPiece where

import PointerSolver.Solver.PcodeDeducer.PcodeDeducer (Deducer)

-- output = SUBPIECE input0 input1

data SubPiece where
  SubPiece :: SubPiece

instance Deducer SubPiece
