{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}
module Network.SSH.Compression
  ( Compression(..)
  , allCompression
  , compression_none
#ifdef SSH_HANS_SUPPORT_COMPRESSION
  , compression_zlib
#endif
  ) where

import qualified Data.ByteString as S
import qualified Data.ByteString.Lazy as L

import           Network.SSH.Named
#ifdef SSH_HANS_SUPPORT_COMPRESSION
import           Network.SSH.ZlibCompression
#endif

data Compression = Compression
  { makeCompress   :: IO (S.ByteString -> IO L.ByteString)
  , makeDecompress :: IO (S.ByteString -> IO L.ByteString)
  }

-- The order of this list is interpreted as preference order
-- in 'allAlgsSshProposalPrefs'.
allCompression :: [Named Compression]
allCompression =
  [ compression_none
#ifdef SSH_HANS_SUPPORT_COMPRESSION
  , compression_zlib
#endif
  ]

compression_none :: Named Compression
compression_none = Named "none" (Compression mknoop mknoop)
  where mknoop = return (return . L.fromStrict)

#ifdef SSH_HANS_SUPPORT_COMPRESSION
compression_zlib :: Named Compression
compression_zlib = Named "zlib" (Compression mkZlibCompressor mkZlibDecompressor)
#endif
