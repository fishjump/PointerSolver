{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE GADTs #-}

module PointerSolver.Type.ControlFlowGraph.BasicBlock where

import Data.Aeson (FromJSON, ToJSON)
import Data.Set (Set)
import GHC.Generics (Generic)
import qualified PointerSolver.Type.BasicBlock.Id as Type.BasicBlock

data BasicBlock where
  BasicBlock ::
    { preds :: Set Type.BasicBlock.Id,
      succs :: Set Type.BasicBlock.Id
    } ->
    BasicBlock
  deriving (Generic, Show)

instance ToJSON BasicBlock

instance FromJSON BasicBlock