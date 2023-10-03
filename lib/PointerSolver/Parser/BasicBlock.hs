{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE InstanceSigs #-}

module PointerSolver.Parser.BasicBlock where

-- import Data.Aeson (FromJSON)
import GHC.Generics (Generic)
import PointerSolver.Parser.BasicBlockId (BasicBlockId)
import PointerSolver.Parser.PcodeId (PcodeId)
import Text.JSON

data BasicBlock = BasicBlock
  { -- id :: BasicBlockId,
    entry :: String,
    exit :: String
    -- pred :: [BasicBlockId],
    -- succ :: [BasicBlockId],
    -- pcode :: [PcodeId]
  }
  deriving (Generic, Show)

-- instance FromJSON BasicBlock

instance JSON BasicBlock where
  readJSON :: JSValue -> Result BasicBlock
  readJSON (JSObject obj) = BasicBlock <$> entry <*> exit
    where
      entry = valFromObj "entry" obj
      exit = valFromObj "exit" obj
  readJSON _ = Error "BasicBlock must be an object"

  showJSON :: BasicBlock -> JSValue
  showJSON _ = undefined

-- instance FromJSON BasicBlock where
--   parseJSON :: Value -> Parser BasicBlock
--   parseJSON =
