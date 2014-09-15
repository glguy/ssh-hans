module Main where

import Tests.Messages
import Tests.Packet
-- import Tests.Protocol

import Test.Framework ( testGroup )
import Test.Framework.Runners.Console ( defaultMain )


main :: IO ()
main  = defaultMain
  [ testGroup "Messages" messageTests
  , testGroup "Packet"   packetTests
  --, testGroup "Protocol" protocolTests
  ]
