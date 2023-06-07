{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE GADTs #-}

module PointerSolver.Solver.FSM.States where

import GHC.Generics (Generic)

data Type where
  Int :: Type
  Bool :: Type
  Float :: Type
  Pointer :: Type
  PointerOfPointer :: Type
  Unknown :: Type
  deriving (Generic, Show, Eq)

data Event where
  ToInt :: Event
  ToBool :: Event
  ToFloat :: Event
  ToPointer :: Event
  ToPointerOfPointer :: Event
  Idle :: Event
  deriving (Generic, Show, Eq)

transition :: Event -> Type -> Type
-- ToInt: from Unknown
transition ToInt Unknown = Int
-- ToBool: from Unknown
transition ToBool Unknown = Bool
-- ToFloat: from Unknown
transition ToFloat Unknown = Float
-- ToPointer: from Pointer
transition ToPointer Int = Pointer
-- ToPointerOfPointer: from pointer to POfP
transition ToPointerOfPointer Pointer = PointerOfPointer
-- Otherwise, do nothinng
transition _ t = t

toSome :: Type -> Event
toSome Int = ToInt
toSome Bool = ToBool
toSome Float = ToFloat
toSome Pointer = ToPointer
toSome PointerOfPointer = ToPointerOfPointer
toSome _ = Idle