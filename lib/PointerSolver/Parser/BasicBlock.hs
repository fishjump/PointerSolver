{-# LANGUAGE DeriveGeneric #-}

module PointerSolver.Parser.BasicBlock where

import GHC.Generics (Generic)
import PointerSolver.Parser.BasicBlockId (BasicBlockId)
import PointerSolver.Parser.PcodeId (PcodeId)

data BasicBlock = BasicBlock
  { id :: BasicBlockId,
    entry :: String,
    exit :: String,
    pred :: [BasicBlockId],
    succ :: [BasicBlockId],
    pcode :: [PcodeId]
  }
  deriving (Generic, Show)
