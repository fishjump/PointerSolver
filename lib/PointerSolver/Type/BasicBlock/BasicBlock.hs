{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE GADTs #-}

module PointerSolver.Type.BasicBlock.BasicBlock where

import Data.Aeson (FromJSON, ToJSON)
import Data.Map (Map)
import GHC.Generics (Generic)
import qualified PointerSolver.Type.BasicBlock.Id as BasicBlock
import qualified PointerSolver.Type.Pcode.Id as Pcode

data BasicBlock where
  BasicBlock ::
    { id :: BasicBlock.Id,
      entry :: String,
      exit :: String,
      pcodes :: [Pcode.Id]
    } ->
    BasicBlock
  deriving (Generic, Show)

instance ToJSON BasicBlock

instance FromJSON BasicBlock