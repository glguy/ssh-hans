{-# LANGUAGE OverloadedStrings #-}

module Network.SSH.Keys where

import           Network.SSH.Messages ( SshSessionId(..) )
import           Network.SSH.Protocol ( putMpInt )

import qualified Data.ByteString as S
import qualified Data.ByteString.Lazy as L
import           Data.Serialize ( runPut, putByteString )


data KeyPair = KeyPair { kpClientToServer :: L.ByteString
                       , kpServerToClient :: L.ByteString
                       } deriving (Show)

data Keys = Keys { kInitialIV :: !KeyPair
                 , kEncKey    :: !KeyPair
                 , kIntegKey  :: !KeyPair
                 } deriving (Show)

genKeys :: (S.ByteString -> S.ByteString)
        -> Integer -> S.ByteString -> SshSessionId
        -> Keys
genKeys hash k h session_id =
  Keys { kInitialIV = KeyPair { kpClientToServer = mkKey "A"
                              , kpServerToClient = mkKey "B"
                              }
       , kEncKey    = KeyPair { kpClientToServer = mkKey "C"
                              , kpServerToClient = mkKey "D"
                              }
       , kIntegKey  = KeyPair { kpClientToServer = mkKey "E"
                              , kpServerToClient = mkKey "F"
                              }
       }

  where
  mkKey = genKey hash k h session_id


-- | Generate an initial key stream.  Note, that the returned lazy bytestring is
-- an infinite list of chunks, so just take as much as is necessary.
genKey :: (S.ByteString -> S.ByteString)
       -> Integer -> S.ByteString -> SshSessionId
       -> S.ByteString -> L.ByteString
genKey hash k h (SshSessionId session_id) = \ x ->
  let k_1 = chunk (L.fromChunks [ x, session_id ])
   in k_1 `L.append` chunks k_1
  where

  kh            = runPut (putMpInt k >> putByteString h)
  chunk k_prev  = L.fromStrict (hash (kh `S.append` L.toStrict k_prev))

  chunks k_prev = k_n `L.append` chunks (k_prev `L.append` k_n)
    where
    k_n = chunk k_prev
