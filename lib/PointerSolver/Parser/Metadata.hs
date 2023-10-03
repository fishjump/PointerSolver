{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE OverloadedStrings #-}

module PointerSolver.Parser.Metadata where

import Data.Aeson (FromJSON (parseJSON), FromJSONKey (fromJSONKey), Key, Object, Value (Object), fromJSON, withObject, (.:))
import Data.Aeson.KeyMap
import qualified Data.Aeson.KeyMap as KeyMap
import Data.Aeson.Types (Parser)
import Data.Function ((&))
import Data.List.Split.Internals (Chunk (Text))
import Data.Map (mapKeys, (!))
import qualified Data.Map as Map
import Data.Map.Strict (Map)
import Data.Text
import GHC.Generics (Generic, Meta)
import PointerSolver.Parser.BasicBlock (BasicBlock)
import PointerSolver.Parser.BasicBlockId (BasicBlockId (BasicBlockId))
import PointerSolver.Parser.Pcode (Pcode, Varnode)
import PointerSolver.Parser.PcodeId (PcodeId)
import PointerSolver.Parser.Symbol (Symbol)
import PointerSolver.Parser.SymbolId (SymbolId)
import Text.JSON

newtype Metadata = Metadata
  { f :: [Function]
  }
  deriving (Generic, Show)

instance JSON Metadata where
  readJSON :: JSValue -> Result Metadata
  readJSON (JSObject obj) = Metadata <$> func_list
    where
      func_list = valFromObj "functions" obj
  readJSON _ = Error "Metadata must be an object"

  showJSON :: Metadata -> JSValue
  showJSON _ = undefined

data Function = Function
  { name :: String,
    entry :: String,
    exit :: String,
    varnode :: [Varnode],
    basicblock :: Map BasicBlockId BasicBlock
    -- ,
    -- pcode :: Map PcodeId Pcode,
    -- symbol :: Map SymbolId Symbol
  }
  deriving (Generic, Show)

instance JSON Function where
  readJSON :: JSValue -> Result Function
  readJSON (JSObject obj) = Function <$> name <*> entry <*> exit <*> varnode <*> basicblock
    where
      -- <*> basicblock <*> pcode <*> symbol

      name = valFromObj "name" obj
      entry = valFromObj "entry" obj
      exit = valFromObj "exit" obj
      varnode = valFromObj "varnodes" obj
      basicblock = readJSON (JSObject obj) :: Result (Map BasicBlockId BasicBlock)

  -- pcode = valFromObj "pcode" obj
  -- symbol = valFromObj "symbol" obj
  readJSON _ = Error "Function must be an object"

  showJSON :: Function -> JSValue
  showJSON _ = undefined
