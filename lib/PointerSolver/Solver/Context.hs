{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE GADTs #-}

module PointerSolver.Solver.Context where

import Data.Function ((&))
import Data.Map (Map)
import qualified Data.Map as Map
import Data.Maybe (fromMaybe)
import GHC.Generics (Generic)
import PointerSolver.Solver.FSM.States (Type (Unknown))
import PointerSolver.Type.Varnode.Varnode (Varnode)

data Context where
  Context ::
    { varnode2Type :: Map Varnode Type
    } ->
    Context
  deriving (Show, Generic)

new :: Context
new = Context Map.empty

get :: Varnode -> Context -> Type
get k ctx = ctx & varnode2Type & Map.lookup k & fromMaybe Unknown

set :: Varnode -> Type -> Context -> Context
set k v ctx = ctx & varnode2Type & Map.insert k v & Context

merge :: Context -> Context -> Context
merge (Context m1) (Context m2) = Context $ Map.union m1 m2