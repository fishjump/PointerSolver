{-# LANGUAGE BlockArguments #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# OPTIONS_GHC -Wno-unused-local-binds #-}

module Main where

import qualified Data.Aeson
import Data.ByteString.Lazy.Char8 (pack)
import Data.Function ((&))
import qualified Data.Map as Map
import Data.Maybe (fromJust, fromMaybe, isJust)
import Data.Set (Set)
import qualified Data.Set as Set
import PointerSolver.Solver.Context (Context)
import qualified PointerSolver.Solver.Context as Solver.Context
import qualified PointerSolver.Solver.FSM.States as Type
import PointerSolver.Solver.Solver (solveFunction)
import PointerSolver.Solver.UDChain.UDChain (Varnode, udChain)
import qualified PointerSolver.Type.Function as Function
import qualified PointerSolver.Type.Metadata as Metadata
import qualified PointerSolver.Type.Symbol.Symbol as Symbol
import System.Environment (getArgs)
import Text.Show.Pretty (ppShow)

input :: IO (Maybe String)
input = do
  args <- getArgs

  pure $ case args of
    [] -> Nothing
    (x : _) -> Just x

filterFunctions :: IO [String]
filterFunctions = tail <$> getArgs

metadata :: IO Metadata.Metadata
metadata = do
  file <- input
  jsonStr <- readFile $ fromMaybe "main.json" file
  case Data.Aeson.eitherDecode $ pack jsonStr of
    Left err -> error err
    Right value -> return value

functions :: IO [Function.Function]
functions = do
  meta <- metadata
  filter <- filterFunctions

  return $ [x | x <- Metadata.functions meta, null filter || elem (Function.name x) filter]

handleFunction :: Function.Function -> Context
handleFunction f = do
  let c = udChain f
  let result = solveFunction Solver.Context.new f c
  result

showResult :: Function.Function -> Context -> (Set Varnode, Set Varnode)
showResult f ctx =
  let ghidraPositive =
        f
          & Function.symbols
          & Map.toList
          & filter (\(_, s) -> Symbol.isPointer s)
          & filter (\(_, s) -> Symbol.representative s & isJust)
          & map (\(_, s) -> Symbol.representative s & fromJust)
          & Set.fromList
      solverPositive =
        ctx
          & Solver.Context.varnode2Type
          & Map.toList
          & filter (\(_, t) -> t == Type.Pointer)
          & map fst
          & Set.fromList
   in (ghidraPositive, solverPositive)

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

  let (ghidra, solver) =
        zipWith showResult fs ctxs
          & foldr
            (\(g, s) (g_acc, s_acc) -> (Set.union g g_acc, Set.union s s_acc))
            (Set.empty, Set.empty)

  putStrLn "Result:"
  putStrLn $ "    Ghidra Pointers:" ++ ppShow ghidra
  putStrLn $ "    Solver Pointers:" ++ ppShow solver
  putStrLn $ "    True Positive: " ++ show (merged & (\(a, _, _, _) -> a))
  putStrLn $ "    False Positive: " ++ show (merged & (\(_, a, _, _) -> a))
  putStrLn $ "    True Negative: " ++ show (merged & (\(_, _, a, _) -> a))
  putStrLn $ "    False Negative: " ++ show (merged & (\(_, _, _, a) -> a))
  putStrLn $ "    Accuracy (Positive): " ++ show (merged & (\(a, b, _, _) -> fromIntegral a / fromIntegral (a + b)))
  putStrLn $ "    Accuracy (Negative): " ++ show (merged & (\(_, _, a, b) -> fromIntegral a / fromIntegral (a + b)))
