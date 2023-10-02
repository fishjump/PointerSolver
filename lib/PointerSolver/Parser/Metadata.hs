{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE OverloadedStrings #-}

module PointerSolver.Parser.Metadata where

import Data.Aeson (FromJSON (parseJSON), FromJSONKey (fromJSONKey), Key, Object, Value, fromJSON, withObject, (.:))
import Data.Aeson.KeyMap
import Data.Aeson.Types (Parser)
import Data.Function ((&))
import Data.List.Split.Internals (Chunk (Text))
import Data.Map (Map)
import qualified Data.Map as Map
import Data.Text
import GHC.Generics (Generic)
import PointerSolver.Parser.BasicBlock (BasicBlock)
import PointerSolver.Parser.BasicBlockId (BasicBlockId (BasicBlockId))
import PointerSolver.Parser.Pcode (Pcode, Varnode)
import PointerSolver.Parser.PcodeId (PcodeId)
import PointerSolver.Parser.Symbol (Symbol)
import PointerSolver.Parser.SymbolId (SymbolId)

newtype Metadata = Metadata
  { f :: [Function]
  }
  deriving (Generic, Show)

instance FromJSON Metadata

data Function = Function
  { name :: String,
    entry :: String,
    exit :: String,
    varnode :: [Varnode],
    basicblock :: Map BasicBlockId BasicBlock,
    pcode :: Map PcodeId Pcode,
    symbol :: Map SymbolId Symbol
  }
  deriving (Generic, Show)

-- instance FromJSON Function where
--   parseJSON :: Value -> Parser Function
--   parseJSON = withObject "Function" $ \o ->
--     let name = o .: "name"
--         entry = o .: "entry"
--         exit = o .: "exit"
--         varnode = o .: "varnodes"
--         basicblock = parseBasicBlock o
--         pcode = o .: "pcodes"
--         symbol = o .: "symbols"
--      in Function <$> name <*> entry <*> exit <*> varnode <*> basicblock <*> pcode <*> symbol

-- parseBasicBlock :: Object -> Parser (Map BasicBlockId BasicBlock)
parseBasicBlock o = do
  let map = toMap o
  map' <- Map.map (parseJSON :: Value -> Parser BasicBlock) map

  map'

-- parseKeyValue :: Key -> Value -> Parser (BasicBlockId, BasicBlock)
-- parseKeyValue k v = do
--   -- key <- parseBasicBlockId k
--   -- value <- parseJSON v
--   -- pure (key, value)
--   undefined