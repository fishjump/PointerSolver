{-# LANGUAGE DeriveGeneric #-}

module PointerSolver.Parser.BasicBlockId where

import Data.Aeson (FromJSON, FromJSONKey (fromJSONKey), Key)
import Data.Aeson.Types
import GHC.Generics (Generic)

newtype BasicBlockId = BasicBlockId String
  deriving (Generic, Show, Eq, Ord)

instance FromJSON BasicBlockId

instance FromJSONKey BasicBlockId
