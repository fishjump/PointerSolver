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
    op :: PcodeOp,
    parent :: BasicBlockId,
    input :: [Varnode],
    output :: Maybe Varnode
  }
  deriving (Generic, Show)

instance FromJSON Pcode
