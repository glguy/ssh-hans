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

  , mac_umac_64
  , mac_umac_64_etm
  , mac_umac_128
  , mac_umac_128_etm
  ) where

import           Data.ByteString.Short (ShortByteString)
import qualified Data.ByteString.Char8 as S
import qualified Data.ByteString.Lazy as L
import           Data.Serialize ( runPut, putWord32be, putWord64be )
import           Data.Word ( Word32 )

import           Crypto.Error
import qualified Crypto.MAC.HMAC as HMAC
import qualified Crypto.Hash as Hash
import qualified Crypto.MAC.UMAC as UMAC
import           Data.ByteArray (convert)

import Network.SSH.Named

data Mac = Mac
  { computeMac  :: Word32 -> [S.ByteString] -> S.ByteString
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

  , mac_umac_64
  , mac_umac_64_etm
  , mac_umac_128
  , mac_umac_128_etm
  ]

-- Algorithms ------------------------------------------------------------------

mac_none :: Named (L.ByteString -> Mac)
mac_none  = Named "none" $ \_ ->
  Mac { computeMac  = \_ _ -> S.empty
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
  Mac { computeMac  = \seqNum bytes ->
                        convert (hmac' h key (runPut (putWord32be seqNum) : bytes))
      , mETM        = etm
      }

truncateMac :: Int -> Named (L.ByteString -> Mac) -> Named (L.ByteString -> Mac)
truncateMac n = fmap $ fmap $ \mac -> mac
  { computeMac = \a b -> S.take n (computeMac mac a b) }


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

------------------------------------------------------------------------

mk_umac ::
  ([S.ByteString] -> S.ByteString -> S.ByteString -> CryptoFailable S.ByteString) ->
  ShortByteString -> Bool -> Named (L.ByteString -> Mac)
mk_umac f name etm = Named name $ \keyStream ->
  let key = L.toStrict (L.take (fromIntegral UMAC.keySize) keyStream) in
  Mac { computeMac  = \seqNum input ->
                        let nonce = runPut (putWord64be (fromIntegral seqNum))
                            CryptoPassed mac = f input key nonce
                        in mac
      , mETM        = etm
      }

mac_umac_64 :: Named (L.ByteString -> Mac)
mac_umac_64 = mk_umac UMAC.compute64 "umac-64@openssh.com" False

mac_umac_64_etm :: Named (L.ByteString -> Mac)
mac_umac_64_etm = mk_umac UMAC.compute64 "umac-64-etm@openssh.com" True

mac_umac_128 :: Named (L.ByteString -> Mac)
mac_umac_128 = mk_umac UMAC.compute128 "umac-128@openssh.com" False

mac_umac_128_etm :: Named (L.ByteString -> Mac)
mac_umac_128_etm = mk_umac UMAC.compute128 "umac-128-etm@openssh.com" True
