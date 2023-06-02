{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE GADTs #-}

module PointerSolver.Type.ControlFlowGraph.BasicBlock where

import Data.Aeson (FromJSON, ToJSON)
import GHC.Generics (Generic)
import qualified PointerSolver.Type.BasicBlock.Id as Type.BasicBlock

data BasicBlock where
  BasicBlock ::
    { preds :: [Type.BasicBlock.Id],
      succs :: [Type.BasicBlock.Id]
    } ->
    BasicBlock
  deriving (Generic, Show)

instance ToJSON BasicBlock

instance FromJSON BasicBlock