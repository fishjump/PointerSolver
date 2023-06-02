{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE GADTs #-}

module PointerSolver.Type.ControlFlowGraph.Pcode where

import Data.Aeson (FromJSON, ToJSON)
import GHC.Generics (Generic)
import qualified PointerSolver.Type.Pcode.Id as Type.Pcode

data Pcode where
  Pcode ::
    { preds :: [Type.Pcode.Id],
      succs :: [Type.Pcode.Id]
    } ->
    Pcode
  deriving (Generic, Show)

instance ToJSON Pcode

instance FromJSON Pcode