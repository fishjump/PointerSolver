{-# LANGUAGE DeriveGeneric #-}

module PointerSolver.Parser.Pcode where

import GHC.Generics (Generic)
import PointerSolver.Parser.BasicBlockId (BasicBlockId)
import PointerSolver.Parser.PcodeId (PcodeId)
import PointerSolver.Parser.PcodeOp (PcodeOp)

data Pcode = Pcode
  { id :: PcodeId,
    op :: PcodeOp,
    parent :: BasicBlockId,
    input :: [Varnode],
    output :: Maybe Varnode
  }
  deriving (Generic, Show)

newtype Varnode = Varnode String
  deriving (Generic, Show)
