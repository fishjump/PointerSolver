-- {-# LANGUAGE GADTs #-}

module PointerSolver.Solver.BasicBlockSolver where

-- import Data.Function ((&))
-- import Data.Map (Map)
-- import qualified Data.Map as Map
-- import Data.Maybe (fromMaybe)
-- import qualified PointerSolver.Solver.FSM.States as State
-- import PointerSolver.Solver.PcodeDeducer.MapPcodeOpToDeducer (stage1Deducer)
-- import PointerSolver.Type.BasicBlock.BasicBlock (BasicBlock)
-- import qualified PointerSolver.Type.BasicBlock.BasicBlock as BasicBlock
-- import qualified PointerSolver.Type.BasicBlock.Id as BasicBlock
-- import qualified PointerSolver.Type.Pcode.Id as Pcode
-- import PointerSolver.Type.Pcode.Pcode (Pcode)
-- import qualified PointerSolver.Type.Pcode.Pcode as Pcode

-- data BasicBlockSummary where
--   BasicBlockSummary ::
--     {
--     } ->
--     BasicBlockSummary

-- solveBasicBlock :: BasicBlock -> (Pcode.Id -> State.Type -> BasicBlockSummary)
-- solveBasicBlock = solveBasicBlock'

-- solveBasicBlock' :: BasicBlock -> BasicBlock.Id -> State.Type -> BasicBlockSummary
-- solveBasicBlock' meta (x : xs) id t = stage1Deducer
--   where
--     pcodeOp = meta & Map.lookup x & fromMaybe (error ("Failed to find pcode id: " ++ id)) & Pcode.operation

-- -- solveBasicBlock ctx func udctx