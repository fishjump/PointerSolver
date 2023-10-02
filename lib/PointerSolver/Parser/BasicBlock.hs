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
    pred :: [BasicBlockId],
    succ :: [BasicBlockId],
    pcode :: [PcodeId]
  }
  deriving (Generic, Show)

instance FromJSON BasicBlock

-- instance FromJSON BasicBlock where
--   parseJSON :: Value -> Parser BasicBlock
--   parseJSON =
