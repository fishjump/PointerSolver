{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE GADTs #-}

module PointerSolver.Type.Function where

import Data.Aeson (FromJSON, ToJSON)
import Data.Map (Map)
import GHC.Generics (Generic)
import PointerSolver.Type.BasicBlock.BasicBlock (BasicBlock)
import qualified PointerSolver.Type.BasicBlock.Id as BasicBlock
import PointerSolver.Type.ControlFlowGraph.ControlFlowGraph (ControlFlowGraph)
import PointerSolver.Type.Pcode.Pcode (Pcode)
import qualified PointerSolver.Type.Symbol.Id as Pcode
import qualified PointerSolver.Type.Symbol.Id as Symbol
import PointerSolver.Type.Symbol.Symbol (Symbol)
import PointerSolver.Type.Varnode.Varnode (Varnode)

data Function where
  Function ::
    { name :: String,
      entry :: String,
      exit :: String,
      basicblocks :: Map BasicBlock.Id BasicBlock,
      pcodes :: Map Pcode.Id Pcode,
      varnodes :: [Varnode],
      symbols :: Map Symbol.Id Symbol,
      cfg :: ControlFlowGraph
    } ->
    Function
  deriving (Generic, Show)

instance ToJSON Function

instance FromJSON Function