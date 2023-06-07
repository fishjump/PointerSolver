{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE TypeFamilies #-}

module PointerSolver.Solver.PcodeDeducer.Helper where

import PointerSolver.Solver.FSM.States (Event (Idle), Type)
import PointerSolver.Type.Varnode.Varnode (Varnode)
import qualified PointerSolver.Type.Varnode.Varnode as Varnode

guardType :: [Type] -> Type -> Event -> Event
guardType ts t e
  | t `elem` ts = e
  | otherwise = Idle

guardTypeAny :: [Type] -> [Type] -> Event -> Event
guardTypeAny ts ts' e
  | any (`elem` ts) ts' = e
  | otherwise = Idle

guardSize :: Int -> Varnode -> Event -> Event
guardSize size varnode e
  | Varnode.size varnode == size = e
  | otherwise = Idle
