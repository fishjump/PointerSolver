{-# LANGUAGE DeriveGeneric #-}

module PointerSolver.Parser.BasicBlockId where

import GHC.Generics (Generic)

newtype BasicBlockId = BasicBlockId String
  deriving (Generic, Show)
