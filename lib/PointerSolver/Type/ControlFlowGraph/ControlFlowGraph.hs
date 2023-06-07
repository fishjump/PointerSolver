{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE GADTs #-}

module PointerSolver.Type.ControlFlowGraph.ControlFlowGraph where

import Data.Aeson (FromJSON, ToJSON)
import Data.Map (Map)
import GHC.Generics (Generic)
import qualified PointerSolver.Type.BasicBlock.Id as BasicBlock
import qualified PointerSolver.Type.ControlFlowGraph.BasicBlock as ControlFlowGraph
import qualified PointerSolver.Type.ControlFlowGraph.Pcode as ControlFlowGraph
import qualified PointerSolver.Type.Pcode.Id as Pcode

data ControlFlowGraph where
  ControlFlowGraph ::
    { basicblocks :: Map BasicBlock.Id ControlFlowGraph.BasicBlock,
      pcodes :: Map Pcode.Id ControlFlowGraph.Pcode
    } ->
    ControlFlowGraph
  deriving (Generic, Show)

instance ToJSON ControlFlowGraph

instance FromJSON ControlFlowGraph