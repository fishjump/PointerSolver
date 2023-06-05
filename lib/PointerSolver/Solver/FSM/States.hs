{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE GADTs #-}

module PointerSolver.Solver.FSM.States where

import Control.Monad.State (MonadState (get, put), State)
import GHC.Generics (Generic)

data Type where
  Int :: Type
  Bool :: Type
  Float :: Type
  Pointer :: Type
  PointerOfPointer :: Type
  Unknown :: Type
  deriving (Generic, Show)

data Event where
  ToInt :: Event
  ToBool :: Event
  ToFloat :: Event
  ToPointer :: Event
  ToPointerOfPointer :: Event
  Idle :: Event
  deriving (Generic, Show)

transition :: Event -> State Type ()
-- ToInt: from Unknown
transition ToInt = do
  s <- get
  put $ case s of
    Unknown -> Int
-- ToBool: from Unknown
transition ToBool = do
  s <- get
  put $ case s of
    Unknown -> Bool
-- ToFloat: from Unknown
transition ToFloat = do
  s <- get
  put $ case s of
    Unknown -> Float
-- ToPointer: from Pointer
transition ToPointer = do
  s <- get
  put $ case s of
    Int -> Bool
-- ToPointerOfPointer: from pointer to POfP
transition ToPointerOfPointer = do
  s <- get
  put $ case s of
    Int -> Bool
-- Idle: Do nothinng
transition Idle = do
  s <- get
  put s