{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE OverloadedStrings #-}

module PointerSolver.Parser.PcodeOp where

import qualified Data.Aeson as Aeson
import Data.Aeson.Types (FromJSON (parseJSON), ToJSON, withText)
import qualified Data.Aeson.Types as Aeson
import GHC.Generics (Generic)

data PcodeOp
  = INT_EQUAL -- Int Logic Op --
  | INT_NOTEQUAL
  | INT_LESS
  | INT_SLESS
  | INT_LESSEQUAL
  | INT_SLESSEQUAL
  | INT_CARRY
  | INT_SCARRY
  | INT_SBORROW
  | INT_ADD -- Int Bin Op --
  | INT_SUB
  | INT_XOR
  | INT_AND
  | INT_OR
  | INT_LEFT
  | INT_RIGHT
  | INT_SRIGHT
  | INT_MULT
  | INT_DIV
  | INT_REM
  | INT_SDIV
  | INT_SREM
  | INT_ZEXT -- Int Unary Op --
  | INT_SEXT
  | INT_2COMP
  | INT_NEGATE
  | FLOAT_EQUAL -- Float Cmp Op --
  | FLOAT_NOT_EQUAL
  | FLOAT_LESS
  | FLOAT_LESS_EQUAL
  | FLOAT_ADD -- Float Bin Op --
  | FLOAT_SUB
  | FLOAT_MULT
  | FLOAT_DIV
  | FLOAT_NEG -- Float Unary Op --
  | FLOAT_ABS
  | FLOAT_SQRT
  | FLOAT_CEIL
  | FLOAT_FLOOR
  | FLOAT_ROUND
  | FLOAT_NAN
  | BOOL_XOR -- Bool Bin Op --
  | BOOL_AND
  | BOOL_OR
  | BOOL_NEGATE -- Bool Unary Op --
  | COPY
  | LOAD
  | STORE
  | BRANCH
  | CBRANCH
  | BRANCHIND
  | CALL
  | CALLIND
  | RETURN
  | PIECE
  | SUBPIECE
  | INT2FLOAT
  | FLOAT2FLOAT
  | TRUNC
  | PTRADD
  | PTRSUB
  | POPCOUNT -- TODO --
  | MULTIEQUAL
  | CAST
  | INDIRECT
  | UNKNOWN
  deriving (Generic, Show)

instance ToJSON PcodeOp

instance FromJSON PcodeOp where
  parseJSON :: Aeson.Value -> Aeson.Parser PcodeOp
  parseJSON = withText "parsing PcodeOp" $ \t -> return $ case t of
    -- Int Logic Op --
    "INT_EQUAL" -> INT_EQUAL
    "INT_NOTEQUAL" -> INT_NOTEQUAL
    "INT_LESS" -> INT_LESS
    "INT_SLESS" -> INT_SLESS
    "INT_LESSEQUAL" -> INT_LESSEQUAL
    "INT_SLESSEQUAL" -> INT_SLESSEQUAL
    "INT_CARRY" -> INT_CARRY
    "INT_SCARRY" -> INT_SCARRY
    "INT_SBORROW" -> INT_SBORROW
    -- Int Bin Op --
    "INT_ADD" -> INT_ADD
    "INT_SUB" -> INT_SUB
    "INT_XOR" -> INT_XOR
    "INT_AND" -> INT_AND
    "INT_OR" -> INT_OR
    "INT_LEFT" -> INT_LEFT
    "INT_RIGHT" -> INT_RIGHT
    "INT_SRIGHT" -> INT_SRIGHT
    "INT_MULT" -> INT_MULT
    "INT_DIV" -> INT_DIV
    "INT_REM" -> INT_REM
    "INT_SDIV" -> INT_SDIV
    "INT_SREM" -> INT_SREM
    -- Int Unary Op --
    "INT_ZEXT" -> INT_ZEXT
    "INT_SEXT" -> INT_SEXT
    "INT_2COMP" -> INT_2COMP
    "INT_NEGATE" -> INT_NEGATE
    -- Float Cmp Op --
    "FLOAT_EQUAL" -> FLOAT_EQUAL
    "FLOAT_NOT_EQUAL" -> FLOAT_NOT_EQUAL
    "FLOAT_LESS" -> FLOAT_LESS
    "FLOAT_LESS_EQUAL" -> FLOAT_LESS_EQUAL
    -- Float Bin Op --
    "FLOAT_ADD" -> FLOAT_ADD
    "FLOAT_SUB" -> FLOAT_SUB
    "FLOAT_MULT" -> FLOAT_MULT
    "FLOAT_DIV" -> FLOAT_DIV
    -- Float Unary Op --
    "FLOAT_NEG" -> FLOAT_NEG
    "FLOAT_ABS" -> FLOAT_ABS
    "FLOAT_SQRT" -> FLOAT_SQRT
    "FLOAT_CEIL" -> FLOAT_CEIL
    "FLOAT_FLOOR" -> FLOAT_FLOOR
    "FLOAT_ROUND" -> FLOAT_ROUND
    "FLOAT_NAN" -> FLOAT_NAN
    -- Bool Bin Op --
    "BOOL_XOR" -> BOOL_XOR
    "BOOL_AND" -> BOOL_AND
    "BOOL_OR" -> BOOL_OR
    -- Bool Unary Op --
    "BOOL_NEGATE" -> BOOL_NEGATE
    "COPY" -> COPY
    "LOAD" -> LOAD
    "STORE" -> STORE
    "BRANCH" -> BRANCH
    "CBRANCH" -> CBRANCH
    "BRANCHIND" -> BRANCHIND
    "CALL" -> CALL
    "CALLIND" -> CALLIND
    "RETURN" -> RETURN
    "PIECE" -> PIECE
    "SUBPIECE" -> SUBPIECE
    "INT2FLOAT" -> INT2FLOAT
    "FLOAT2FLOAT" -> FLOAT2FLOAT
    "TRUNC" -> TRUNC
    "PTRADD" -> PTRADD
    "PTRSUB" -> PTRSUB
    -- TODO --
    "POPCOUNT" -> POPCOUNT
    "MULTIEQUAL" -> MULTIEQUAL
    "CAST" -> CAST
    "INDIRECT" -> INDIRECT
    _ -> UNKNOWN
