{-# LANGUAGE TupleSections #-}

module PointerSolver.Solver.UDChain.UDChain where

import Data.Function ((&))
import qualified Data.Map as Map
import Data.Maybe (isJust)
import qualified Data.Maybe as Maybe
import Data.Set (Set)
import qualified Data.Set as Set
import PointerSolver.Solver.UDChain.Context (Context (Context))
import qualified PointerSolver.Solver.UDChain.Context as Context
import qualified PointerSolver.Type.ControlFlowGraph.ControlFlowGraph as CFG
import qualified PointerSolver.Type.ControlFlowGraph.Pcode as CFG.Pcode
import PointerSolver.Type.Function (Function)
import qualified PointerSolver.Type.Function as Function
import qualified PointerSolver.Type.Pcode.Id as Pcode
import qualified PointerSolver.Type.Pcode.Pcode as Pcode
import PointerSolver.Type.Varnode.Varnode (Varnode)

-- Given a function, a pcode id and a varnode, find where this varnode is defined
-- A context is for one function
-- 1. find if this result is already in the context, return it
-- 2. if it is not, recursively find the preds pcode
defs :: Context -> Function -> Pcode.Id -> Varnode -> (Context, Set Pcode.Id)
defs ctx func id varnode
  | contains (id, varnode) = (ctx, defSet (id, varnode))
  | otherwise =
      let defSet' = defs' Set.empty Set.empty func id varnode
          ctx' = update (id, varnode) defSet'
       in (ctx', defSet')
  where
    udMap = Context.udMap ctx
    contains k = udMap & Map.member k
    defSet k = udMap & Map.lookup k & Maybe.fromMaybe Set.empty
    update k v = Context (Map.insert k v udMap)

-- The helper function for defs
-- 1. if a id is visited, just return it
-- 2. if the current pcode is an assignment and this output is this varnode, add it into this state
-- 3. otherwise, recursively visit the preds
defs' :: Set Pcode.Id -> Set Pcode.Id -> Function -> Pcode.Id -> Varnode -> Set Pcode.Id
defs' visited state func id varnode
  | Set.member id visited = state
  | isAssignment id && varnode `isOutputOf` id = nextWithState state'
  | otherwise = nextWithState state
  where
    visited' = Set.insert id visited
    state' = state & Set.insert id

    isAssignment id =
      let maybePcode = func & Function.pcodes & Map.lookup id
       in case maybePcode of
            Nothing -> False
            Just x -> x & Pcode.output & isJust

    isOutputOf varnode id =
      let maybePcode = func & Function.pcodes & Map.lookup id
       in case maybePcode of
            Nothing -> False
            Just x -> case Pcode.output x of
              Nothing -> False
              Just x' -> x' == varnode

    nextWithState s =
      let preds =
            func
              & Function.cfg
              & CFG.pcodes
              & Map.lookup id
              & maybe Set.empty CFG.Pcode.preds
       in Set.map (\id' -> defs' visited' s func id' varnode) preds & Set.foldr Set.union s

udChain :: Function -> Context
udChain function =
  targets
    & foldr
      ( \(id, varnode) ->
          defs ctx function id varnode
            & fst
            & Context.udMap
            & Map.union
      )
      Map.empty
    & Context
  where
    ctx = Context.new
    pcodes = Function.pcodes function
    zipPcode p = map (Pcode.id p,) (Pcode.inputs p)
    targets = pcodes & (\p -> p & Map.toList & concatMap (\(_, v) -> zipPcode v))
