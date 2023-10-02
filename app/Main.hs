{-# LANGUAGE BlockArguments #-}
{-# OPTIONS_GHC -Wno-unused-local-binds #-}

module Main where

import qualified Data.Aeson
import Data.ByteString.Lazy.Char8 (pack)
import Data.Function ((&))
import qualified Data.Map as Map
import Data.Maybe (fromJust, isJust)
import qualified Data.Set as Set
import PointerSolver.Solver.Context (Context)
import qualified PointerSolver.Solver.Context as Solver.Context
import qualified PointerSolver.Solver.FSM.States as Type
import PointerSolver.Solver.Solver (solveFunction)
import PointerSolver.Solver.UDChain.UDChain (udChain)
import qualified PointerSolver.Type.Function as Function
import qualified PointerSolver.Type.Metadata as Metadata
import qualified PointerSolver.Type.Symbol.Symbol as Symbol

metadata :: IO Metadata.Metadata
metadata = do
  let file = "main.json"
  jsonStr <- readFile file
  case Data.Aeson.eitherDecode $ pack jsonStr of
    Left err -> error err
    Right value -> return value

functions :: IO [Function.Function]
functions = do
  meta <- metadata
  return $ meta & Metadata.functions

function :: IO Function.Function
function = do
  meta <- metadata
  return $ meta & Metadata.functions & head

handleFunction :: Function.Function -> Context
handleFunction f = do
  let c = udChain f
  let result = solveFunction Solver.Context.new f c
  result

calResult :: Function.Function -> Context -> (Int, Int, Int, Int)
calResult f ctx =
  let ghidraPositive =
        f
          & Function.symbols
          & Map.toList
          & filter (\(_, s) -> Symbol.isPointer s)
          & filter (\(_, s) -> Symbol.representative s & isJust)
          & map (\(_, s) -> Symbol.representative s & fromJust)
          & Set.fromList

      ghidraNegative =
        f
          & Function.varnodes
          & Set.fromList
          & \x -> Set.difference x ghidraPositive

      solverPositive =
        ctx
          & Solver.Context.varnode2Type
          & Map.toList
          & filter (\(_, t) -> t == Type.Pointer)
          & map fst
          & Set.fromList

      solverNegative =
        f
          & Function.varnodes
          & Set.fromList
          & \x -> Set.difference x solverPositive

      -- True Positive
      tpSet = Set.intersection ghidraPositive solverPositive

      -- False Positive (in the solver but not in ghidra)
      fpSet = Set.difference solverPositive ghidraPositive

      -- True Negative
      tnSet = Set.intersection ghidraNegative solverNegative

      -- False Negative (in solver but not in the ghidra)
      fnSet = Set.difference solverNegative ghidraNegative
   in (Set.size tpSet, Set.size fpSet, Set.size tnSet, Set.size fnSet)

main :: IO ()
main = do
  fs <- functions
  let ctxs = map handleFunction fs

  let results = zipWith calResult fs ctxs
  let merged = foldr (\(a, b, c, d) (a', b', c', d') -> (a + a', b + b', c + c', d + d')) (0, 0, 0, 0) results

  putStrLn "Result:"
  putStrLn $ "    True Positive: " ++ show (merged & (\(a, _, _, _) -> a))
  putStrLn $ "    False Positive: " ++ show (merged & (\(_, a, _, _) -> a))
  putStrLn $ "    True Negative: " ++ show (merged & (\(_, _, a, _) -> a))
  putStrLn $ "    False Negative: " ++ show (merged & (\(_, _, _, a) -> a))
  putStrLn $ "    Accuracy (Positive): " ++ show (merged & (\(a, b, _, _) -> fromIntegral a / fromIntegral (a + b)))
  putStrLn $ "    Accuracy (Negative): " ++ show (merged & (\(_, _, a, b) -> fromIntegral a / fromIntegral (a + b)))

  -- printf "True Positive: %d\n" $ merged & (\(a, _, _, _) -> a)
  -- printf "False Positive: %d\n" $ merged & (\(_, a, _, _) -> a)
  -- printf "True Negative: %d\n" $ merged & (\(_, _, a, _) -> a)
  -- printf "False Negative: %d\n" $ merged & (\(_, _, _, a) -> a)
  -- printf "Accuracy (Positive): %f\n" $ merged & (\(a, b, _, _) -> fromIntegral a / fromIntegral (a + b))
  -- printf "Accuracy (Negative): %f\n" $ merged & (\(_, _, a, b) -> fromIntegral a / fromIntegral (a + b))
