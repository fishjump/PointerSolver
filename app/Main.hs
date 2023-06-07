{-# LANGUAGE BlockArguments #-}

module Main where

import qualified Data.Aeson
import Data.ByteString.Lazy.Char8 (pack)
import Data.Function ((&))
import qualified Data.Map as Map
import Data.Maybe (fromJust, isJust)
import qualified Data.Set as Set
import qualified PointerSolver.Solver.Context as Solver.Context
import qualified PointerSolver.Solver.FSM.States as Type
import PointerSolver.Solver.Solver (solveFunction)
import PointerSolver.Solver.UDChain.UDChain (udChain)
import qualified PointerSolver.Type.Function as Function
import qualified PointerSolver.Type.Metadata as Metadata
import qualified PointerSolver.Type.Symbol.Symbol as Symbol
import Text.Show.Pretty (ppShow)

metadata :: IO Metadata.Metadata
metadata = do
  let file = "dump3.json"
  jsonStr <- readFile file
  case Data.Aeson.decode $ pack jsonStr of
    Nothing -> error ""
    Just value -> return value

-- For demo reason, handle main function only
function :: IO Function.Function
function =
  metadata
    & fmap
      ( \meta ->
          meta
            & Metadata.functions
            & filter (\f -> Function.name f == "main")
            & head
      )

main :: IO ()
main = do
  f <- function
  let c = udChain f
  let result = solveFunction Solver.Context.new f c

  let ghidraPositive =
        f
          & Function.symbols
          & Map.toList
          & filter (\(_, s) -> Symbol.isPointer s)
          & filter (\(_, s) -> Symbol.representative s & isJust)
          & map (\(_, s) -> Symbol.representative s & fromJust)
          & Set.fromList

  let ghidraNegative =
        f
          & Function.varnodes
          & Set.fromList
          & \x -> Set.difference x ghidraPositive

  let solverPositive =
        result
          & Solver.Context.varnode2Type
          & Map.toList
          & filter (\(_, t) -> t == Type.Pointer)
          & map fst
          & Set.fromList

  let solverNegative =
        f
          & Function.varnodes
          & Set.fromList
          & \x -> Set.difference x solverPositive

  -- True Positive
  let tpSet = Set.intersection ghidraPositive solverPositive

  -- False Positive (in the solver but not in ghidra)
  let fpSet = Set.difference solverPositive ghidraPositive

  -- True Negative
  let tnSet = Set.intersection ghidraNegative solverNegative

  -- False Negative (in solver but not in the ghidra)
  let fnSet = Set.difference solverNegative ghidraNegative

  putStrLn $ "Result: " ++ ppShow result
  putStrLn $ "True Positive: " ++ ppShow tpSet
  putStrLn $ "False Positive: " ++ ppShow fpSet
  putStrLn $ "True Negative: " ++ ppShow tnSet
  putStrLn $ "False Negative: " ++ ppShow fnSet
