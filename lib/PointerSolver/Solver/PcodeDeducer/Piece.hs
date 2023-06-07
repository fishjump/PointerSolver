{-# LANGUAGE GADTs #-}

module PointerSolver.Solver.PcodeDeducer.Piece where

import PointerSolver.Solver.PcodeDeducer.PcodeDeducer (Deducer)

-- output = PIECE input0 input1

data Piece where
  Piece :: Piece

instance Deducer Piece
