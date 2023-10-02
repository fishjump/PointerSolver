{-# LANGUAGE DeriveGeneric #-}

module PointerSolver.Parser.PcodeId where

import Data.Aeson (FromJSON, FromJSONKey, fromJSONKey)
import GHC.Generics (Generic)

newtype PcodeId = PcodeId String
  deriving (Generic, Show, Eq, Ord)

instance FromJSON PcodeId

instance FromJSONKey PcodeId
