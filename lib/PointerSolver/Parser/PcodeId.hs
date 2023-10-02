{-# LANGUAGE DeriveGeneric #-}

module PointerSolver.Parser.PcodeId where

import GHC.Generics (Generic)

newtype PcodeId = PcodeId String
  deriving (Generic, Show)
