{-# LANGUAGE DeriveGeneric #-}

module PointerSolver.Parser.SymbolId where

import Data.Aeson (FromJSON, FromJSONKey)
import GHC.Generics (Generic)

newtype SymbolId = SymbolId String
  deriving (Generic, Show, Eq, Ord)

instance FromJSON SymbolId

instance FromJSONKey SymbolId
