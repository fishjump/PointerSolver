{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE GADTs #-}

module PointerSolver.Type.ControlFlowGraph.Pcode where

import Data.Aeson (FromJSON, ToJSON)
import Data.Set (Set)
import GHC.Generics (Generic)
import qualified PointerSolver.Type.Pcode.Id as Type.Pcode

data Pcode where
  Pcode ::
    { preds :: Set Type.Pcode.Id,
      succs :: Set Type.Pcode.Id
    } ->
    Pcode
  deriving (Generic, Show)

instance ToJSON Pcode

instance FromJSON Pcode