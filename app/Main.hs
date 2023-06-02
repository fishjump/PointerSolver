module Main where

import Data.Aeson (eitherDecode)
import Data.ByteString.Lazy.Char8 (pack)
import PointerSolver.Type.Metadata (Metadata)

main :: IO ()
main = do
  let file = "dump.json"
  jsonStr <- readFile file
  let maybeValue = eitherDecode $ pack jsonStr :: Either String Metadata
  case maybeValue of
    Left err -> putStrLn err
    Right value -> print value
