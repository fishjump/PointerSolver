{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE GADTs #-}

module PointerSolver.Type.Metadata where

import Data.Aeson (FromJSON, ToJSON)
import GHC.Generics (Generic)
import PointerSolver.Type.Function (Function)

data Metadata where
  Metadata :: {functions :: [Function]} -> Metadata
  deriving (Generic, Show)

instance ToJSON Metadata

instance FromJSON Metadata