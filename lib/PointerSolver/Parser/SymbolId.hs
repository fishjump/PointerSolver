{-# LANGUAGE DeriveGeneric #-}

module PointerSolver.Parser.SymbolId where

import GHC.Generics (Generic)

newtype SymbolId = SymbolId String
  deriving (Generic, Show)