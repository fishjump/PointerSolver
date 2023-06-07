{-# LANGUAGE BlockArguments #-}
{-# LANGUAGE GADTs #-}
{-# OPTIONS_GHC -Wno-unrecognised-pragmas #-}

module PointerSolver.Solver.Solver where

import Data.Function ((&))
import qualified Data.Map as Map
import qualified Data.Maybe as Maybe
import Data.Set (Set)
import qualified Data.Set as Set
import PointerSolver.Solver.Context (merge)
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
      ( \id ->
          ctx
            & (\c -> solveStage1 c func Set.empty id udChainCtx)
            & (\c -> solveStage2 c func Set.empty id udChainCtx)
            & (\c -> solveStage3 c func Set.empty id udChainCtx)
            & merge
      )
      ctx
  where
    ids = func & Function.pcodes & Map.keysSet & Set.toList

solvePcode :: (PcodeOp -> Solver.Context -> Pcode -> Solver.Context) -> Solver.Context -> Function -> Set Pcode.Id -> Pcode.Id -> UDChain.Context -> Solver.Context
solvePcode deducer ctx func visited id udChainCtx
  | Set.member id visited = ctx
  | otherwise =
      pcodeInputs
        & concatMap
          ( \varnode ->
              defs udChainCtx func id varnode
                & snd
                & Set.toList
                & map (\id' -> solvePcode deducer ctx' func visited' id' udChainCtx)
          )
        & foldr merge ctx'
  where
    pcode = func & Function.pcodes & Map.lookup id & Maybe.fromMaybe (error ("solveStage1: pcode not found: " ++ show id))
    pcodeOp = pcode & Pcode.operation
    pcodeInputs = pcode & Pcode.inputs
    deducer' = deducer pcodeOp
    ctx' = deducer' ctx pcode
    visited' = Set.insert id visited

solveStage1 :: Solver.Context -> Function -> Set Pcode.Id -> Pcode.Id -> UDChain.Context -> Solver.Context
solveStage1 = solvePcode stage1Deducer

solveStage2 :: Solver.Context -> Function -> Set Pcode.Id -> Pcode.Id -> UDChain.Context -> Solver.Context
solveStage2 = solvePcode stage2Deducer

solveStage3 :: Solver.Context -> Function -> Set Pcode.Id -> Pcode.Id -> UDChain.Context -> Solver.Context
solveStage3 = solvePcode stage3Deducer
