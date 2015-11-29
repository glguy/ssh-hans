{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.SSH.Mac (
    Mac()
  , mETM
  , computeMac

  , allMac

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

import           Data.ByteString.Short (ShortByteString)
import qualified Data.ByteString.Char8 as S
import qualified Data.ByteString.Lazy as L
import           Data.Serialize ( runPut, putWord32be )
import           Data.Word ( Word32 )

import qualified Crypto.MAC.HMAC as HMAC
import qualified Crypto.Hash as Hash
import           Data.ByteArray (convert)

import Network.SSH.Named

data Mac = Mac
  { mFunction   :: [S.ByteString] -> S.ByteString
  , mETM        :: Bool
  }

allMac :: [ Named (L.ByteString -> Mac) ]
allMac =
  [ mac_none
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
  ]

-- | Sign a packet, yielding out a signature, and the new Mac to use.
computeMac :: Word32 -> Mac -> [S.ByteString] -> S.ByteString
computeMac seqNum Mac { .. } bytes = sig
  where
  sig = mFunction (runPut (putWord32be seqNum) : bytes)


-- Algorithms ------------------------------------------------------------------

mac_none :: Named (L.ByteString -> Mac)
mac_none  = Named "none" $ \_ ->
  Mac { mFunction   = const S.empty
      , mETM        = False
      }

mk_mac_hmac ::
  Hash.HashAlgorithm a =>
  a ->
  ShortByteString {- ^ name -} ->
  Bool {- ^ encrypt then modify -} ->
  Named (L.ByteString -> Mac) {- ^ keystream argument -}
mk_mac_hmac h name etm = Named name $ \keyStream ->
  let keySize = fromIntegral (Hash.hashDigestSize h)
      key = L.toStrict (L.take keySize keyStream) in
  Mac { mFunction   = convert . hmac' h key
      , mETM        = etm
      }

truncateMac :: Int -> Named (L.ByteString -> Mac) -> Named (L.ByteString -> Mac)
truncateMac n = fmap $ fmap $ \mac -> mac { mFunction = S.take n . mFunction mac }


-- | A helper that calls 'HMAC.hmac' using an argument to select the hash
hmac' ::
  Hash.HashAlgorithm a =>
  a ->
  S.ByteString {- ^ key     -} ->
  [S.ByteString] {- ^ message chunks -} ->
  HMAC.HMAC a
hmac' _ key
  = HMAC.finalize
  . HMAC.updates (HMAC.initialize key)

mac_hmac_md5 :: Named (L.ByteString -> Mac)
mac_hmac_md5 = mk_mac_hmac Hash.MD5 "hmac-md5" False

mac_hmac_md5_96 :: Named (L.ByteString -> Mac)
mac_hmac_md5_96 = truncateMac 12 $ mk_mac_hmac Hash.MD5 "hmac-md5-96" False

mac_hmac_ripemd160 :: Named (L.ByteString -> Mac)
mac_hmac_ripemd160 = mk_mac_hmac Hash.RIPEMD160 "hmac-ripemd160" False

mac_hmac_sha1 :: Named (L.ByteString -> Mac)
mac_hmac_sha1 = mk_mac_hmac Hash.SHA1 "hmac-sha1" False

mac_hmac_sha1_96 :: Named (L.ByteString -> Mac)
mac_hmac_sha1_96 = truncateMac 12 $ mk_mac_hmac Hash.SHA1 "hmac-sha1-96" False

mac_hmac_sha2_256 :: Named (L.ByteString -> Mac)
mac_hmac_sha2_256 = mk_mac_hmac Hash.SHA256 "hmac-sha2-256" False

mac_hmac_sha2_512 :: Named (L.ByteString -> Mac)
mac_hmac_sha2_512 = mk_mac_hmac Hash.SHA512 "hmac-sha2-512" False



mac_hmac_md5_etm :: Named (L.ByteString -> Mac)
mac_hmac_md5_etm = mk_mac_hmac Hash.MD5 "hmac-md5-etm@openssh.com" True

mac_hmac_md5_96_etm :: Named (L.ByteString -> Mac)
mac_hmac_md5_96_etm = truncateMac 12 $ mk_mac_hmac Hash.MD5 "hmac-md5-96-etm@openssh.com" True

mac_hmac_ripemd160_etm :: Named (L.ByteString -> Mac)
mac_hmac_ripemd160_etm = mk_mac_hmac Hash.RIPEMD160 "hmac-ripemd160-etm@openssh.com" True

mac_hmac_sha1_etm :: Named (L.ByteString -> Mac)
mac_hmac_sha1_etm = mk_mac_hmac Hash.SHA1 "hmac-sha1-etm@openssh.com" True

mac_hmac_sha1_96_etm :: Named (L.ByteString -> Mac)
mac_hmac_sha1_96_etm = truncateMac 12 $ mk_mac_hmac Hash.SHA1 "hmac-sha1-96-etm@openssh.com" True

mac_hmac_sha2_256_etm :: Named (L.ByteString -> Mac)
mac_hmac_sha2_256_etm = mk_mac_hmac Hash.SHA256 "hmac-sha2-256-etm@openssh.com" True

mac_hmac_sha2_512_etm :: Named (L.ByteString -> Mac)
mac_hmac_sha2_512_etm = mk_mac_hmac Hash.SHA512 "hmac-sha2-512-etm@openssh.com" True
