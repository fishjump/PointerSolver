{-# LANGUAGE DeriveGeneric #-}

module PointerSolver.Parser.Symbol where

import Data.Aeson (FromJSON)
import GHC.Generics (Generic)
import PointerSolver.Parser.Pcode (Varnode)
import PointerSolver.Parser.SymbolId (SymbolId)

data Symbol = Symbol
  { id :: SymbolId,
    dataType :: String,
    length :: Int,
    isPointer :: Bool,
    representative :: Maybe Varnode
  }
  deriving (Generic, Show)

instance FromJSON Symbol
