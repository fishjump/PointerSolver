{-# LANGUAGE DeriveGeneric #-}

module PointerSolver.Parser.Metadata where

import Data.Aeson (FromJSON)
import Data.Map (Map)
import GHC.Generics (Generic)
import PointerSolver.Parser.BasicBlock (BasicBlock)
import PointerSolver.Parser.BasicBlockId (BasicBlockId)
import PointerSolver.Parser.Pcode (Pcode, Varnode)
import PointerSolver.Parser.PcodeId (PcodeId)
import PointerSolver.Parser.Symbol (Symbol)
import PointerSolver.Parser.SymbolId (SymbolId)

newtype Metadata = Metadata
  { functions :: [Function]
  }
  deriving (Generic, Show)

instance FromJSON Metadata

data Function = Function
  { name :: String,
    entry :: String,
    exit :: String,
    varnodes :: [Varnode],
    basicblocks :: Map BasicBlockId BasicBlock,
    pcodes :: Map PcodeId Pcode,
    symbols :: Map SymbolId Symbol
  }
  deriving (Generic, Show)

instance FromJSON Function
