{-# LANGUAGE OverloadedStrings #-}

-- | Key exchange and key generation
module Network.SSH.Keys where

import           Network.SSH.Protocol ( putMpInt, i2os, os2i )
import           Network.SSH.Named
import           Network.SSH.Messages
import           Network.SSH.PubKey

import qualified Data.ByteString as S
import qualified Data.ByteString.Lazy as L
import           Data.Serialize

import           Crypto.Number.Serialize
import           Crypto.Random
import           Crypto.Error
import qualified Crypto.Hash as Hash
import qualified Crypto.PubKey.Curve25519 as C25519
import qualified Crypto.PubKey.DH as DH
import qualified Crypto.PubKey.ECC.DH as ECDH
import qualified Crypto.PubKey.ECC.Types as ECC
import           Data.ByteArray (convert)


data CipherKeys = CipherKeys
  { ckInitialIV :: L.ByteString
  , ckEncKey    :: L.ByteString
  }

nullKeys :: CipherKeys
nullKeys = CipherKeys "" ""

data Keys = Keys
  { k_c2s_cipherKeys :: CipherKeys
  , k_s2c_cipherKeys :: CipherKeys
  , k_c2s_integKey   :: L.ByteString
  , k_s2c_integKey   :: L.ByteString
  }

genKeys ::
  (S.ByteString -> S.ByteString) {- ^ hash function -} ->
  S.ByteString {- ^ shared secret       -} ->
  SshSessionId {- ^ current session_id  -} ->
  SshSessionId {- ^ original session_id -} ->
  Keys
genKeys hash k sid osid = Keys
  { k_c2s_cipherKeys = CipherKeys
      { ckInitialIV = mkKey "A"
      , ckEncKey    = mkKey "C"
      }
  , k_s2c_cipherKeys = CipherKeys
      { ckInitialIV = mkKey "B"
      , ckEncKey    = mkKey "D"
      }
  , k_c2s_integKey  = mkKey "E"
  , k_s2c_integKey  = mkKey "F"
  }
  where
  mkKey = genKey hash k sid osid


-- | Generate an initial key stream.  Note, that the returned lazy bytestring is
-- an infinite list of chunks, so just take as much as is necessary.
genKey ::
  (S.ByteString -> S.ByteString) {- ^ hash function -} ->
  S.ByteString {- ^ shared secret -} ->
  SshSessionId {- ^ current session  id -} ->
  SshSessionId {- ^ original session id -} ->
  S.ByteString {- ^ key name (A-F)      -} ->
  L.ByteString
genKey hash k (SshSessionId h) (SshSessionId o) = \ x ->
  let k_1 = chunk (L.fromChunks [ x, o ])
   in k_1 `L.append` chunks k_1
  where

  kh            = k `S.append` h
  chunk k_prev  = L.fromStrict (hash (kh `S.append` L.toStrict k_prev))

  chunks k_prev = k_n `L.append` chunks (k_prev `L.append` k_n)
    where
    k_n = chunk k_prev

data Kex = Kex
  { kexRun :: IO (S.ByteString, S.ByteString -> Maybe S.ByteString)
     -- ^ (local public, remote public -> shared secret)
  , kexHash :: S.ByteString -> S.ByteString
  }

-- Note that the public values are "raw" encodings while the secret
-- value is not. A raw encoding is not prefixed with its length
-- making it suitable for being parsed and rendered with getString.
-- The secret value, however, is fully encoded because the secret
-- key material is actually derived from the encoded version and
-- the encoded version is never transmitted in a packet.

allKex :: [ Named Kex ]
allKex =
  [ diffieHellmanGroup1Sha1
  , diffieHellmanGroup14Sha1
  , ecdhSha2Nistp256
  , ecdhSha2Nistp384
  , ecdhSha2Nistp521
  , curve25519sha256
  ]

diffieHellmanGroup1Sha1 :: Named Kex
diffieHellmanGroup1Sha1
  = Named "diffie-hellman-group1-sha1" Kex
  { kexRun  = runDh group1
  , kexHash = convert . Hash.hashWith Hash.SHA1
  }

diffieHellmanGroup14Sha1 :: Named Kex
diffieHellmanGroup14Sha1
  = Named "diffie-hellman-group14-sha1" Kex
  { kexRun  = runDh group14
  , kexHash = convert . Hash.hashWith Hash.SHA1
  }

ecdhSha2Nistp256 :: Named Kex
ecdhSha2Nistp256
  = Named "ecdh-sha2-nistp256" Kex
  { kexRun  = runEcdh (ECC.getCurveByName ECC.SEC_p256r1)
  , kexHash = convert . Hash.hashWith Hash.SHA256
  }

ecdhSha2Nistp384 :: Named Kex
ecdhSha2Nistp384
  = Named "ecdh-sha2-nistp384" Kex
  { kexRun  = runEcdh (ECC.getCurveByName ECC.SEC_p384r1)
  , kexHash = convert . Hash.hashWith Hash.SHA384
  }

ecdhSha2Nistp521 :: Named Kex
ecdhSha2Nistp521
  = Named "ecdh-sha2-nistp521" Kex
  { kexRun  = runEcdh (ECC.getCurveByName ECC.SEC_p521r1)
  , kexHash = convert . Hash.hashWith Hash.SHA512
  }

runDh ::
  DH.Params ->
  IO (S.ByteString, S.ByteString -> Maybe S.ByteString)
   {- ^ local public value, remote public -> shared secret -}
runDh params =

  do priv <- DH.generatePrivate params

     let DH.PublicNumber pub_s = DH.calculatePublic params priv

         computeSecret raw_pub_c = Just (runPut (putMpInt shared))
           where
           DH.SharedKey shared = DH.getShared params priv
                               $ DH.PublicNumber
                               $ os2i raw_pub_c


     return (i2os pub_s, computeSecret)


-- |Group 2 from RFC 2409
group1 :: DH.Params
group1 = DH.Params
  { DH.params_p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF
  , DH.params_g = 2
  }

group14 :: DH.Params
group14 = DH.Params
  { DH.params_p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
  , DH.params_g = 2
  }

runEcdh ::
  ECC.Curve ->
  IO (S.ByteString, S.ByteString -> Maybe S.ByteString)
      {- ^ local public value, remote public -> shared secret -}
runEcdh curve =

  do priv <- ECDH.generatePrivate curve

     let serialize = pointToBytes curve

         pub_s     = ECDH.calculatePublic curve priv

         computeSecret raw_pub_c
           | CryptoPassed pub_c <- pointFromBytes curve raw_pub_c
           , let ECDH.SharedKey shared = ECDH.getShared curve priv pub_c
           = Just (runPut (putMpInt shared))

           | otherwise = Nothing

     return (serialize pub_s, computeSecret)

------------------------------------------------------------------------

curve25519sha256 :: Named Kex
curve25519sha256
  = Named "curve25519-sha256@libssh.org" Kex
  { kexRun  = runCurve25519dh
  , kexHash = convert . Hash.hashWith Hash.SHA256
  }

-- | Implements key exchange as defined by
-- curve25519-sha256@libssh.org.txt
runCurve25519dh ::
  IO (S.ByteString, S.ByteString -> Maybe S.ByteString)
  {- ^ local public, remote public -> shared key -}
runCurve25519dh =

     -- fails if key isn't 32 bytes long
  do CryptoPassed priv <- fmap C25519.secretKey
                               (getRandomBytes 32 :: IO S.ByteString)

     -- Section 2: Transmit public key as "string"
     let raw_pub_s  = convert $ C25519.toPublic priv

         computeSecret raw_pub_c
             -- fails if key isn't 32 bytes long
           | CryptoPassed pub_c <- C25519.publicKey raw_pub_c

             -- Section 4.3: Treat shared key bytes as "integer"
           = Just $ runPut $ putMpInt $ os2ip $ C25519.dh pub_c priv

           | otherwise = Nothing


     return (raw_pub_s, computeSecret)
