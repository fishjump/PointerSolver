{-# LANGUAGE BlockArguments #-}

module Main where

import qualified Data.Aeson
import Data.ByteString.Lazy.Char8 (pack)
import Data.Function ((&))
import qualified PointerSolver.Solver.Context as Solver.Context
import PointerSolver.Solver.Solver
import PointerSolver.Solver.UDChain.UDChain (udChain)
import qualified PointerSolver.Type.Function as Function
import qualified PointerSolver.Type.Metadata as Metadata
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
  putStrLn $ ppShow $ solveFunction Solver.Context.new f c
