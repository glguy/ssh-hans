{-# LANGUAGE OverloadedStrings #-}

-- | Key exchange and key generation
module Network.SSH.Keys where

import           Network.SSH.Protocol ( getString, getMpInt, putMpInt, putString )
import           Network.SSH.Named
import           Network.SSH.Messages
import           Network.SSH.PubKey

import qualified Data.ByteString as S
import qualified Data.ByteString.Lazy as L
import           Data.Serialize ( runGet, runPut )

import           Crypto.Number.Serialize
import           Crypto.Random
import           Crypto.Error
import qualified Crypto.Hash as Hash
import qualified Crypto.PubKey.Curve25519 as C25519
import qualified Crypto.PubKey.DH as DH
import qualified Crypto.PubKey.ECC.DH as ECDH
import qualified Crypto.PubKey.ECC.Types as ECC
import qualified Crypto.PubKey.RSA.PKCS15 as RSA
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

genKeys :: (S.ByteString -> S.ByteString)
        -> S.ByteString -> SshSessionId
        -> Keys
genKeys hash k sid = Keys
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
  mkKey = genKey hash k sid


-- | Generate an initial key stream.  Note, that the returned lazy bytestring is
-- an infinite list of chunks, so just take as much as is necessary.
genKey :: (S.ByteString -> S.ByteString)
       -> S.ByteString -> SshSessionId
       -> S.ByteString -> L.ByteString
genKey hash k (SshSessionId h) = \ x ->
  let k_1 = chunk (L.fromChunks [ x, h ])
   in k_1 `L.append` chunks k_1
  where

  kh            = k `S.append` h
  chunk k_prev  = L.fromStrict (hash (kh `S.append` L.toStrict k_prev))

  chunks k_prev = k_n `L.append` chunks (k_prev `L.append` k_n)
    where
    k_n = chunk k_prev

data Kex = Kex
  { kexRun :: S.ByteString -> IO (S.ByteString, S.ByteString)
  , kexHash :: S.ByteString -> S.ByteString
  }

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
  S.ByteString                    {- ^ encoded client public value -} ->
  IO (S.ByteString, S.ByteString) {- ^ server public value, shared secret -}
runDh params raw_pub_c =
  do pub_c <- case runGet getMpInt raw_pub_c of
                Right pub_c -> return pub_c
                Left e      -> fail e
     priv <- DH.generatePrivate params
     let DH.PublicNumber pub_s = DH.calculatePublic params priv
         DH.SharedKey shared = DH.getShared params priv (DH.PublicNumber pub_c)
     return (runPut (putMpInt pub_s), runPut (putMpInt shared))

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
  S.ByteString                    {- ^ encoded client public value -} ->
  IO (S.ByteString, S.ByteString) {- ^ server public value, shared secret -}
runEcdh curve raw_pub_c =

  do pub_c <- case runGet getString raw_pub_c of
                Left _ -> fail "bad client public point 1"
                Right raw_pub_c1 ->
                  case pointFromBytes curve raw_pub_c1 of
                    CryptoFailed _ -> fail "bad client public point"
                    CryptoPassed pub_c -> return pub_c

     priv <- ECDH.generatePrivate curve

     let pub_s     = ECDH.calculatePublic curve priv
         raw_pub_s = runPut (putString (pointToBytes curve pub_s))

         ECDH.SharedKey shared = ECDH.getShared curve priv pub_c
         raw_shared            = runPut (putMpInt shared)

     return (raw_pub_s, raw_shared)

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
  S.ByteString                    {- ^ client public -} ->
  IO (S.ByteString, S.ByteString) {- ^ server public, shared key -}
runCurve25519dh raw_pub_c =

     -- Section 2: Transmit public key as "string"
  do pub_bytes_c <- case runGet getString raw_pub_c of
                      Left _       -> fail "bad client public point 1"
                      Right pub_bytes -> return pub_bytes

     -- fails if key isn't 32 bytes long
     pub_c <- case C25519.publicKey pub_bytes_c of
                CryptoFailed _     -> fail "bad client public point 2"
                CryptoPassed pub_c -> return pub_c

     -- fails if key isn't 32 bytes long
     CryptoPassed priv <- fmap C25519.secretKey
                               (getRandomBytes 32 :: IO S.ByteString)

         -- Section 2: Transmit public key as "string"
     let raw_pub_s  = runPut $ putString $ convert
                    $ C25519.toPublic priv

         -- Section 4.3: Treat shared key bytes as "integer"
         raw_secret = runPut $ putMpInt $ os2ip
                    $ C25519.dh pub_c priv

     return (raw_pub_s, raw_secret)
