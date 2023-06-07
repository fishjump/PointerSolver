{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE GADTs #-}

module PointerSolver.Type.Symbol.Symbol where

import Data.Aeson (FromJSON, ToJSON)
import GHC.Generics (Generic)
import qualified PointerSolver.Type.Symbol.Id as Symbol
import PointerSolver.Type.Varnode.Varnode (Varnode)

data Symbol where
  Symbol ::
    { id :: Symbol.Id,
      dataType :: String,
      length :: Int,
      isPointer :: Bool,
      representative :: Maybe Varnode
    } ->
    Symbol
  deriving (Generic, Show)

instance ToJSON Symbol

instance FromJSON Symbol