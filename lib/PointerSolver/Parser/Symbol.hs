{-# LANGUAGE DeriveGeneric #-}

module PointerSolver.Parser.Symbol where

import GHC.Generics (Generic)
import PointerSolver.Parser.Pcode (Varnode)
import PointerSolver.Parser.SymbolId (SymbolId)

data Symbol = Symbol
  { id :: SymbolId,
    data_type :: String,
    length :: Int,
    is_pointer :: Bool,
    repr :: Maybe Varnode
  }
  deriving (Generic, Show)
