{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.SSH.Mac (
    Mac()
  , mName
  , sign

  , mac_none
  , mac_hmac_sha1
  , mac_hmac_sha2_256
  , mac_hmac_sha2_512
  ) where

import qualified Data.ByteString.Char8 as S
import qualified Data.ByteString.Lazy as L
import           Data.Serialize ( runPut, putWord32be, putByteString )
import           Data.Word ( Word32 )

import qualified Crypto.MAC.HMAC as HMAC
import qualified Crypto.Hash as Hash
import           Data.ByteArray (convert)


data Mac = Mac { mName       :: !S.ByteString
               , mFunction   :: S.ByteString -> S.ByteString
               }

instance Show Mac where
  show Mac { .. } = S.unpack mName

-- | Sign a packet, yielding out a signature, and the new Mac to use.
sign :: Word32 -> Mac -> S.ByteString -> S.ByteString
sign seqNum Mac { .. } bytes = sig
  where
  sig = mFunction (runPut (putWord32be seqNum >> putByteString bytes))


-- Algorithms ------------------------------------------------------------------

mac_none :: Mac
mac_none  =
  Mac { mName       = "none"
      , mFunction   = const S.empty
      }

mk_mac_hmac ::
  Hash.HashAlgorithm a =>
  a ->
  S.ByteString {- ^ name -} ->
  L.ByteString {- ^ key stream -} ->
  Mac
mk_mac_hmac h name = \keyStream ->
  let keySize = fromIntegral (Hash.hashDigestSize h)
      key = L.toStrict (L.take keySize keyStream) in
  Mac { mName       = name
      , mFunction   = convert . hmac' h key
      }

-- | A helper that calls 'HMAC.hmac' using an argument to select the hash
hmac' ::
  Hash.HashAlgorithm a =>
  a ->
  S.ByteString {- ^ key     -} ->
  S.ByteString {- ^ message -} ->
  HMAC.HMAC a
hmac' _ = HMAC.hmac

mac_hmac_sha1 :: L.ByteString -> Mac
mac_hmac_sha1 = mk_mac_hmac Hash.SHA1 "hmac-sha1"

mac_hmac_sha2_256 :: L.ByteString -> Mac
mac_hmac_sha2_256 = mk_mac_hmac Hash.SHA256 "hmac-sha2-256"

mac_hmac_sha2_512 :: L.ByteString -> Mac
mac_hmac_sha2_512 = mk_mac_hmac Hash.SHA512 "hmac-sha2-512"
