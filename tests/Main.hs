module Main where

import Tests.Transport

import Test.Framework ( testGroup )
import Test.Framework.Runners.Console ( defaultMain )


main :: IO ()
main  = defaultMain
  [ testGroup "transport" transportTests
  ]
