{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE GADTs #-}

module PointerSolver.Type.Pcode.Pcode where

import Data.Aeson (FromJSON, ToJSON)
import GHC.Generics (Generic)
import qualified PointerSolver.Type.BasicBlock.Id as BasicBlock
import qualified PointerSolver.Type.Pcode.Id as Pcode
import PointerSolver.Type.PcodeOp.PcodeOp (PcodeOp)
import PointerSolver.Type.Varnode.Varnode (Varnode)

data Pcode where
  Pcode ::
    { id :: Pcode.Id,
      operation :: PcodeOp,
      parent :: BasicBlock.Id,
      inputs :: [Varnode],
      output :: Maybe Varnode
    } ->
    Pcode
  deriving (Generic, Show)

instance ToJSON Pcode

instance FromJSON Pcode