module PointerSolver.Type.Varnode.Varnode where

import Data.Function ((&))
import Data.List.Split (splitOn)
import Data.Maybe (fromMaybe)
import Text.Read (readMaybe)

type Varnode = String

size :: Varnode -> Int
size v = v & tail & init & splitOn "," & last & readMaybe & fromMaybe 0
