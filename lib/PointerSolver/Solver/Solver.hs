{-# LANGUAGE BlockArguments #-}
{-# LANGUAGE GADTs #-}
{-# OPTIONS_GHC -Wno-unrecognised-pragmas #-}

module PointerSolver.Solver.Solver where

import Data.Function ((&))
import qualified Data.Map as Map
import qualified Data.Maybe as Maybe
import Data.Set (Set)
import qualified Data.Set as Set
import qualified PointerSolver.Solver.Context as Solver
import PointerSolver.Solver.PcodeDeducer.MapPcodeOpToDeducer (stage1Deducer, stage2Deducer, stage3Deducer)
import qualified PointerSolver.Solver.UDChain.Context as UDChain
import PointerSolver.Solver.UDChain.UDChain (defs)
import PointerSolver.Type.Function (Function)
import qualified PointerSolver.Type.Function as Function
import qualified PointerSolver.Type.Pcode.Id as Pcode
import PointerSolver.Type.Pcode.Pcode (Pcode)
import qualified PointerSolver.Type.Pcode.Pcode as Pcode
import PointerSolver.Type.PcodeOp.PcodeOp (PcodeOp)

solveFunction :: Solver.Context -> Function -> UDChain.Context -> Solver.Context
solveFunction ctx func udChainCtx =
  ids
    & foldr
      ( \id c ->
          c
            & (\c -> solveStage1 c func Set.empty id udChainCtx)
            & (\c -> solveStage2 c func Set.empty id udChainCtx)
            & (\c -> solveStage3 c func Set.empty id udChainCtx)
      )
      ctx
  where
    ids = func & Function.pcodes & Map.keysSet & Set.toList

solvePcode :: (PcodeOp -> Solver.Context -> Pcode -> Solver.Context) -> Solver.Context -> Function -> Set Pcode.Id -> Pcode.Id -> UDChain.Context -> (Set Pcode.Id, Solver.Context)
solvePcode deducer ctx func visited id udChainCtx
  | Set.member id visited = (visited, ctx)
  | otherwise =
      operands
        & foldr
          ( \v c ->
              defs udChainCtx func id v
                & snd
                & Set.toList
                & foldr
                  (\id (visited, ctx) -> solvePcode deducer ctx func visited id udChainCtx)
                  c
          )
          (visited', ctx')
  where
    pcode = func & Function.pcodes & Map.lookup id & Maybe.fromMaybe (error ("solveStage: pcode not found: " ++ show id))
    operands = pcode & Pcode.inputs
    deducer' = deducer (pcode & Pcode.operation)
    ctx' = deducer' ctx pcode
    visited' = Set.insert id visited

solveStage1 :: Solver.Context -> Function -> Set Pcode.Id -> Pcode.Id -> UDChain.Context -> Solver.Context
solveStage1 ctx func visited id udChainCtx = snd $ solvePcode stage1Deducer ctx func visited id udChainCtx

solveStage2 :: Solver.Context -> Function -> Set Pcode.Id -> Pcode.Id -> UDChain.Context -> Solver.Context
solveStage2 ctx func visited id udChainCtx = snd $ solvePcode stage2Deducer ctx func visited id udChainCtx

solveStage3 :: Solver.Context -> Function -> Set Pcode.Id -> Pcode.Id -> UDChain.Context -> Solver.Context
solveStage3 ctx func visited id udChainCtx = snd $ solvePcode stage3Deducer ctx func visited id udChainCtx
