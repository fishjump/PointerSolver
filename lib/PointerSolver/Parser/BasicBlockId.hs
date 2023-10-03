{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE InstanceSigs #-}

module PointerSolver.Parser.BasicBlockId where

-- import Data.Aeson (FromJSON, FromJSONKey (fromJSONKey), Key)
-- import Data.Aeson.Types
import GHC.Generics (Generic)
import Text.JSON

newtype BasicBlockId = BasicBlockId String
  deriving (Generic, Show, Eq, Ord)

instance JSON BasicBlockId where
  readJSON :: JSValue -> Result BasicBlockId
  readJSON (JSString str) = Ok (BasicBlockId (fromJSString str))
  readJSON _ = Error "BasicBlockId must be a string"

  showJSON :: BasicBlockId -> JSValue
  showJSON _ = undefined
