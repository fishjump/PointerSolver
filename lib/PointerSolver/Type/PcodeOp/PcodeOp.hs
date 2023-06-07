{-# LANGUAGE DeriveGeneric #-}

module PointerSolver.Type.PcodeOp.PcodeOp where

import Data.Aeson (FromJSON, ToJSON)
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
  deriving (Generic, Show)

instance ToJSON PcodeOp

instance FromJSON PcodeOp
