{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.SSH.Mac (
    Mac()
  , mName
  , mETM
  , sign

  , mac_none
  , mac_hmac_md5
  , mac_hmac_md5_96
  , mac_hmac_ripemd160
  , mac_hmac_sha1
  , mac_hmac_sha1_96
  , mac_hmac_sha2_256
  , mac_hmac_sha2_512

  , mac_hmac_md5_etm
  , mac_hmac_md5_96_etm
  , mac_hmac_ripemd160_etm
  , mac_hmac_sha1_etm
  , mac_hmac_sha1_96_etm
  , mac_hmac_sha2_256_etm
  , mac_hmac_sha2_512_etm
  ) where

import qualified Data.ByteString.Char8 as S
import qualified Data.ByteString.Lazy as L
import           Data.Serialize ( runPut, putWord32be, putByteString )
import           Data.Word ( Word32 )

import qualified Crypto.MAC.HMAC as HMAC
import qualified Crypto.Hash as Hash
import           Data.ByteArray (convert)


data Mac = Mac
  { mName       :: !S.ByteString
  , mFunction   :: S.ByteString -> S.ByteString
  , mETM        :: Bool
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
      , mETM        = False
      }

mk_mac_hmac ::
  Hash.HashAlgorithm a =>
  a ->
  S.ByteString {- ^ name -} ->
  Bool {- ^ encrypt then modify -} ->
  L.ByteString {- ^ key stream -} ->
  Mac
mk_mac_hmac h name etm = \keyStream ->
  let keySize = fromIntegral (Hash.hashDigestSize h)
      key = L.toStrict (L.take keySize keyStream) in
  Mac { mName       = name
      , mFunction   = convert . hmac' h key
      , mETM        = etm
      }

truncateMac :: Int -> Mac -> Mac
truncateMac n mac = mac { mFunction = S.take n . mFunction mac }


-- | A helper that calls 'HMAC.hmac' using an argument to select the hash
hmac' ::
  Hash.HashAlgorithm a =>
  a ->
  S.ByteString {- ^ key     -} ->
  S.ByteString {- ^ message -} ->
  HMAC.HMAC a
hmac' _ = HMAC.hmac

mac_hmac_md5 :: L.ByteString -> Mac
mac_hmac_md5 = mk_mac_hmac Hash.MD5 "hmac-md5" False

mac_hmac_md5_96 :: L.ByteString -> Mac
mac_hmac_md5_96 = truncateMac 12 . mk_mac_hmac Hash.MD5 "hmac-md5-96" False

mac_hmac_ripemd160 :: L.ByteString -> Mac
mac_hmac_ripemd160 = mk_mac_hmac Hash.RIPEMD160 "hmac-ripemd160" False

mac_hmac_sha1 :: L.ByteString -> Mac
mac_hmac_sha1 = mk_mac_hmac Hash.SHA1 "hmac-sha1" False

mac_hmac_sha1_96 :: L.ByteString -> Mac
mac_hmac_sha1_96 = truncateMac 12 . mk_mac_hmac Hash.SHA1 "hmac-sha1-96" False

mac_hmac_sha2_256 :: L.ByteString -> Mac
mac_hmac_sha2_256 = mk_mac_hmac Hash.SHA256 "hmac-sha2-256" False

mac_hmac_sha2_512 :: L.ByteString -> Mac
mac_hmac_sha2_512 = mk_mac_hmac Hash.SHA512 "hmac-sha2-512" False



mac_hmac_md5_etm :: L.ByteString -> Mac
mac_hmac_md5_etm = mk_mac_hmac Hash.MD5 "hmac-md5-etm@openssh.com" True

mac_hmac_md5_96_etm :: L.ByteString -> Mac
mac_hmac_md5_96_etm = truncateMac 12 . mk_mac_hmac Hash.MD5 "hmac-md5-96-etm@openssh.com" True

mac_hmac_ripemd160_etm :: L.ByteString -> Mac
mac_hmac_ripemd160_etm = mk_mac_hmac Hash.RIPEMD160 "hmac-ripemd160-etm@openssh.com" True

mac_hmac_sha1_etm :: L.ByteString -> Mac
mac_hmac_sha1_etm = mk_mac_hmac Hash.SHA1 "hmac-sha1-etm@openssh.com" True

mac_hmac_sha1_96_etm :: L.ByteString -> Mac
mac_hmac_sha1_96_etm = truncateMac 12 . mk_mac_hmac Hash.SHA1 "hmac-sha1-96-etm@openssh.com" True

mac_hmac_sha2_256_etm :: L.ByteString -> Mac
mac_hmac_sha2_256_etm = mk_mac_hmac Hash.SHA256 "hmac-sha2-256-etm@openssh.com" True

mac_hmac_sha2_512_etm :: L.ByteString -> Mac
mac_hmac_sha2_512_etm = mk_mac_hmac Hash.SHA512 "hmac-sha2-512-etm@openssh.com" True
