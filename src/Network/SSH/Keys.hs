{-# LANGUAGE OverloadedStrings #-}

module Network.SSH.Keys where

import           Network.SSH.Messages ( SshSessionId(..) )
import           Network.SSH.Protocol ( getString, getMpInt, putMpInt, putString )

import qualified Data.ByteString as S
import qualified Data.ByteString.Lazy as L
import           Data.Serialize ( runGet, runPut )
import           Data.Monoid ((<>))

import           Crypto.Error
import qualified Crypto.PubKey.DH as DH
import qualified Crypto.PubKey.ECC.DH as ECDH
import qualified Crypto.PubKey.ECC.Types as ECDH
import qualified Crypto.PubKey.ECC.P256 as P256
import qualified Crypto.Hash.Algorithms as Hash
import qualified Crypto.Hash as Hash
import           Data.ByteArray (convert)


data KeyPair = KeyPair { kpClientToServer :: L.ByteString
                       , kpServerToClient :: L.ByteString
                       } deriving (Show)

data Keys = Keys { kInitialIV :: !KeyPair
                 , kEncKey    :: !KeyPair
                 , kIntegKey  :: !KeyPair
                 } deriving (Show)

genKeys :: (S.ByteString -> S.ByteString)
        -> S.ByteString -> S.ByteString -> SshSessionId
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
       -> S.ByteString -> S.ByteString -> SshSessionId
       -> S.ByteString -> L.ByteString
genKey hash k h (SshSessionId session_id) = \ x ->
  let k_1 = chunk (L.fromChunks [ x, session_id ])
   in k_1 `L.append` chunks k_1
  where

  kh            = k `S.append` h
  chunk k_prev  = L.fromStrict (hash (kh `S.append` L.toStrict k_prev))

  chunks k_prev = k_n `L.append` chunks (k_prev `L.append` k_n)
    where
    k_n = chunk k_prev

data Kex = Kex
  { kexName :: S.ByteString
  , kexRun :: S.ByteString -> IO (S.ByteString, S.ByteString)
  , kexHash :: S.ByteString -> S.ByteString
  }

diffieHellmanGroup1Sha1 :: Kex
diffieHellmanGroup1Sha1 = Kex
  { kexName = "diffie-hellman-group1-sha1"
  , kexRun  = runDh group1
  , kexHash = convert . Hash.hashWith Hash.SHA1
  }

diffieHellmanGroup14Sha1 :: Kex
diffieHellmanGroup14Sha1 = Kex
  { kexName = "diffie-hellman-group14-sha1"
  , kexRun  = runDh group14
  , kexHash = convert . Hash.hashWith Hash.SHA1
  }

ecdhSha2Nistp256 :: Kex
ecdhSha2Nistp256 = Kex
  { kexName = "ecdh-sha2-nistp256"
  , kexRun  = runEcdhP256
  , kexHash = convert . Hash.hashWith Hash.SHA256
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

runEcdhP256 ::
  S.ByteString                    {- ^ encoded client public value -} ->
  IO (S.ByteString, S.ByteString) {- ^ server public value, shared secret -}
runEcdhP256 raw_pub_c =
  do pub_c <- case runGet getString raw_pub_c of
                Left _ -> fail "bad client public point 1"
                Right raw_pub_c1 ->
                  case nistp256PointFromBinary raw_pub_c1 of
                    CryptoFailed _ -> fail "bad client public point"
                    CryptoPassed pub_c -> return pub_c
     let curve = ECDH.getCurveByName ECDH.SEC_p256r1
     priv <- ECDH.generatePrivate curve
     let pub_s = ECDH.calculatePublic curve priv
         ECDH.SharedKey shared = ECDH.getShared curve priv pub_c
     raw_pub_s <- case pub_s of
                    ECDH.PointO -> fail "public point at infinity"
                    ECDH.Point x y ->
                       do let p = P256.pointFromIntegers (x,y)
                          return ("\4" <> P256.pointToBinary p)
     return (runPut (putString raw_pub_s), runPut (putMpInt shared))

nistp256PointFromBinary :: S.ByteString -> CryptoFailable ECDH.Point
nistp256PointFromBinary bs =
  case S.uncons bs of
    Just (4, bs1) -> -- we don't support compression at this point
      do p <- P256.pointFromBinary bs1
         let (x,y) = P256.pointToIntegers p
         return (ECDH.Point x y)
    _ -> CryptoFailed CryptoError_PublicKeySizeInvalid
