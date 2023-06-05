{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE GADTs #-}

module PointerSolver.Solver.UDChain.Context where

import qualified Control.Applicative as Set
import Data.Map (Map)
import qualified Data.Map as Map
import Data.Set (Set)
import GHC.Generics (Generic)
import qualified PointerSolver.Type.Pcode.Id as Pcode
import PointerSolver.Type.Varnode.Varnode (Varnode)

-- Why (Pcode.Id, Varnode): at which pcode, a varnode is used by which other pcodes
-- Note: varnodes are different in different functions, even though they may have the same
data Context where
  Context ::
    { udMap :: Map (Pcode.Id, Varnode) (Set Pcode.Id)
    } ->
    Context
  deriving (Generic, Show)

new :: Context
new = Context Map.empty
