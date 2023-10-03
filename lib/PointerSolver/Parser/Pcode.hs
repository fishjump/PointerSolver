{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE InstanceSigs #-}

module PointerSolver.Parser.Pcode where

import Data.Aeson (FromJSON)
import GHC.Generics (Generic)
import PointerSolver.Parser.BasicBlockId (BasicBlockId)
import PointerSolver.Parser.PcodeId (PcodeId)
import PointerSolver.Parser.PcodeOp (PcodeOp)
import Text.JSON

newtype Varnode = Varnode String
  deriving (Generic, Show)

instance JSON Varnode where
  readJSON :: JSValue -> Result Varnode
  readJSON (JSString str) = Ok (Varnode (fromJSString str))
  readJSON _ = Error "Varnode must be a string"

  showJSON :: Varnode -> JSValue
  showJSON _ = undefined

data Pcode = Pcode
  { id :: PcodeId,
    op :: PcodeOp,
    parent :: BasicBlockId,
    input :: [Varnode],
    output :: Maybe Varnode
  }
  deriving (Generic, Show)
