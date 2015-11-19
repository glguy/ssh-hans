{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.SSH.Server (

    Server(..)
  , Client(..)
  , SessionEvent(..)
  , AuthResult(..)
  , sshServer

  , PrivateKey()
  , PublicKey()
  , genKeyPair

  ) where

import           Network.SSH.Ciphers
import           Network.SSH.Connection
import           Network.SSH.Keys
import           Network.SSH.Mac
import           Network.SSH.Messages
import           Network.SSH.Packet
import           Network.SSH.State

import           Control.Concurrent
import qualified Control.Exception as X
import           Control.Monad.CryptoRandom ( crandomR )
import           Crypto.Classes.Exceptions ( newGenIO, genBytes, splitGen )
import           Crypto.Random.DRBG ( CtrDRBG )
import           Crypto.Types.PubKey.RSA ( PublicKey(..), PrivateKey(..) )
import           Codec.Crypto.RSA.Exceptions
                     ( modular_exponentiation, rsassa_pkcs1_v1_5_sign, hashSHA1
                     , HashInfo(..), generateKeyPair, generatePQ )
import qualified Data.ByteString.Char8 as S
import qualified Data.ByteString.Lazy as L
import           Data.IORef
                     ( writeIORef, modifyIORef )
import           Data.Serialize
                     ( runPutLazy )

-- Public API ------------------------------------------------------------------

data Server = Server { sAccept :: IO Client
                     }

sshServer :: SshIdent -> PrivateKey -> PublicKey -> Server -> IO ()
sshServer ident privKey pubKey sock = loop =<< newGenIO
  where
  loop g = do client <- sAccept sock
              let (g',gClient) = splitGen g
              _ <- forkIO $
                     do state  <- initialState
                        result <- sayHello state ident gClient privKey pubKey client
                        case result of
                          Nothing -> send client state
                                        (SshMsgDisconnect SshDiscNoMoreAuthMethodsAvailable
                                                 "" "")
                          Just (_user,svc) ->
                            case svc of
                              SshConnection -> startConnectionService client state
                              _             -> return ()

                      `X.finally` cClose client

              loop g'

-- | Generates a 1024-bit RSA key pair.
genKeyPair :: IO (PrivateKey, PublicKey)
genKeyPair  =
  do gen <- newGenIO
     let (pub,priv,_) = generateKeyPair (gen :: CtrDRBG) 1024
         (p,q,_)      = generatePQ gen (1024 `div` 8)
         priv'        = priv { private_p = p, private_q = q }
     return (priv', pub)


-- | Install new keys (and algorithms) into the SshState.
transitionKeys :: Keys -> SshState -> IO ()
transitionKeys Keys { .. } SshState { .. } =
  do writeIORef sshDecC (snd (cipher_aes128_cbc (kpClientToServer kInitialIV) (kpClientToServer kEncKey)))

     modifyIORef sshAuthC $ \ mac ->
       let mac' = mac_hmac_sha1 (kpClientToServer kIntegKey)
        in mac `switch` mac'

     modifyMVar_ sshSendState $ \(_,mac) ->
       let cipher = fst (cipher_aes128_cbc (kpServerToClient kInitialIV)
                                           (kpServerToClient kEncKey))
           mac' = mac_hmac_sha1 (kpServerToClient kIntegKey)
        in return (cipher, mac `switch` mac')

     putStrLn "New keys installed."





sayHello ::
  SshState ->
  SshIdent ->
  CtrDRBG ->
  PrivateKey ->
  PublicKey ->
  Client ->
  IO (Maybe (S.ByteString, SshService))
sayHello state ident gen priv pub client =
  do cPut client (runPutLazy (putSshIdent ident))
     msg   <- parseFrom client (sshBuf state) getSshIdent
     print msg
     case msg of
       Right v_c -> do print v_c
                       startKex gen priv pub (sshDhHash v_c ident) state client
       Left err  -> do print err
                       return Nothing


supportedKex :: SshCookie -> SshKex
supportedKex sshCookie =
  SshKex { sshKexAlgs           = [ "diffie-hellman-group1-sha1" ]
         , sshServerHostKeyAlgs = [ "ssh-rsa" ]
         , sshEncAlgs           = SshAlgs [ "aes128-cbc" ] [ "aes128-cbc" ]
         , sshMacAlgs           = SshAlgs [ "hmac-sha1" ] [ "hmac-sha1" ]
         , sshCompAlgs          = SshAlgs [ "none" ] [ "none" ]
         , sshLanguages         = SshAlgs [] []
         , sshFirstKexFollows   = False
         , ..
         }

newCookie :: CtrDRBG -> (SshCookie,CtrDRBG)
newCookie g = (SshCookie bytes, g')
  where
  (bytes,g') = genBytes 16 g

startKex :: CtrDRBG -> PrivateKey -> PublicKey
         -> (SshKex -> SshKex -> SshPubCert -> Integer -> Integer -> Integer -> S.ByteString)
         -> SshState -> Client -> IO (Maybe (S.ByteString, SshService))
startKex gen priv pub mkHash state client =
  do let (cookie,gen')  = newCookie gen
         i_s            = supportedKex cookie

     send client state (SshMsgKexInit i_s)

     i_c <- waitForClientKex
     putStrLn "Got KexInit"
     startDh client gen' priv pub state (mkHash i_c i_s)
  where
  waitForClientKex =
    do msg <- receive client state
       case msg of
         SshMsgKexInit i_c -> return i_c
         _                 -> waitForClientKex


data DiffieHellmanGroup = DiffieHellmanGroup {
       dhgP    :: Integer -- ^The prime.
     , dhgG    :: Integer -- ^The generator.
     , dhgSize :: Int     -- ^Size in bits.
     }
 deriving (Eq, Show)

-- |Group 2 from RFC 2409
oakley2 :: DiffieHellmanGroup
oakley2 = DiffieHellmanGroup {
    dhgP = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF
  , dhgG = 2
  , dhgSize = 1024
  }

startDh :: Client -> CtrDRBG -> PrivateKey -> PublicKey -> SshState
        -> (SshPubCert -> Integer -> Integer -> Integer -> S.ByteString)
        -> IO (Maybe (S.ByteString, SshService))
startDh client gen priv@PrivateKey{..} pub@PublicKey{..} state mkHash =
  do SshMsgKexDhInit e <- receive client state
     let Right (y,gen') = crandomR (1,private_q) gen
         f              = modular_exponentiation (dhgG oakley2) y (dhgP oakley2)
         k              = modular_exponentiation e y (dhgP oakley2)
         cert           = SshPubRsa public_e public_n
         hash           = mkHash cert e f k
         h              = hashFunction hashSHA1 (L.fromStrict hash)
         h'             = L.toStrict h

         sig            = rsassa_pkcs1_v1_5_sign hashSHA1 priv h

         session_id     = SshSessionId h'
         keys           = genKeys (hashFunction hashSHA1) k h' session_id


     putStrLn "Sending DH reply"
     send client state (SshMsgKexDhReply cert f (SshSigRsa (L.toStrict sig)))

     putStrLn "Waiting for response"
     getDhResponse client gen' priv pub session_id state keys


getDhResponse :: Client -> CtrDRBG -> PrivateKey -> PublicKey -> SshSessionId
              -> SshState -> Keys -> IO (Maybe (S.ByteString, SshService))
getDhResponse client _gen _priv _pub session_id state keys =
  do SshMsgNewKeys <- receive client state
     send client state SshMsgNewKeys

     transitionKeys keys state

     let notAvailable = send client state
                      $ SshMsgDisconnect SshDiscServiceNotAvailable "" "en-us"

     req <- receive client state
     case req of

       SshMsgServiceRequest SshUserAuth ->
         do send client state (SshMsgServiceAccept SshUserAuth)
            authLoop

        where
         authLoop =
           do userReq <- receive client state
              case userReq of

                SshMsgUserAuthRequest user svc method ->
                  do result <- cAuthHandler client session_id user svc method

                     case result of

                       AuthAccepted ->
                         do send client state SshMsgUserAuthSuccess
                            return (Just (user, svc))

                       AuthPkOk keyAlg key ->
                         do send client state
                              (SshMsgUserAuthPkOk keyAlg key)
                            authLoop

                       AuthFailed [] ->
                         do send client state (SshMsgUserAuthFailure [] False)
                            return Nothing

                       AuthFailed ms ->
                         do send client state (SshMsgUserAuthFailure ms False)
                            authLoop


                _ -> notAvailable >> return Nothing

       _ -> notAvailable >> return Nothing
