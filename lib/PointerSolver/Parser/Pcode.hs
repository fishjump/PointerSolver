{-# LANGUAGE DeriveGeneric #-}

module PointerSolver.Parser.Pcode where

import Data.Aeson (FromJSON)
import GHC.Generics (Generic)
import PointerSolver.Parser.BasicBlockId (BasicBlockId)
import PointerSolver.Parser.PcodeId (PcodeId)
import PointerSolver.Parser.PcodeOp (PcodeOp)

newtype Varnode = Varnode String
  deriving (Generic, Show)

instance FromJSON Varnode

data Pcode = Pcode
  { id :: PcodeId,
    operation :: PcodeOp,
    parent :: BasicBlockId,
    inputs :: [Varnode],
    output :: Maybe Varnode,
    preds :: [PcodeId],
    succs :: [PcodeId]
  }
  deriving (Generic, Show)

instance FromJSON Pcode
