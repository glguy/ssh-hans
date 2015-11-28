{-# LANGUAGE OverloadedStrings #-}
module Network.SSH.Compression where

import qualified Data.ByteString as S

import Network.SSH.Named

data Compression = Compression
  { makeCompress   :: IO (S.ByteString -> IO S.ByteString)
  , makeDecompress :: IO (S.ByteString -> IO S.ByteString)
  }

allCompression :: [Named Compression]
allCompression = [compression_none]

compression_none :: Named Compression
compression_none = Named "none" (Compression (return return) (return return))
