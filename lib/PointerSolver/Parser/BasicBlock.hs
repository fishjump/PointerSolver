{-# LANGUAGE DeriveGeneric #-}

module PointerSolver.Parser.BasicBlock where

import Data.Aeson (FromJSON)
import GHC.Generics (Generic)
import PointerSolver.Parser.BasicBlockId (BasicBlockId)
import PointerSolver.Parser.PcodeId (PcodeId)

data BasicBlock = BasicBlock
  { id :: BasicBlockId,
    entry :: String,
    exit :: String,
    preds :: [BasicBlockId],
    succs :: [BasicBlockId],
    pcodes :: [PcodeId]
  }
  deriving (Generic, Show)

instance FromJSON BasicBlock
