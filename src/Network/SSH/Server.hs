{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.SSH.Server (

    Server(..)
  , Client(..)
  , SessionEvent(..)
  , AuthResult(..)
  , sshServer

  ) where

import           Network.SSH.Ciphers
import           Network.SSH.Connection
import           Network.SSH.Keys
import           Network.SSH.Mac
import           Network.SSH.Messages
import           Network.SSH.Packet
import           Network.SSH.State

import           Control.Concurrent
import           Control.Monad (forever)
import qualified Control.Exception as X
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA
import qualified Crypto.Hash.Algorithms as Hash
import qualified Crypto.Hash as Hash
import qualified Crypto.PubKey.DH as DH
import           Crypto.Random (getRandomBytes)
import           Data.ByteArray (convert)
import qualified Data.ByteString.Char8 as S
import           Data.IORef
                     ( writeIORef, modifyIORef )
import           Data.Serialize
                     ( runPutLazy )

-- Public API ------------------------------------------------------------------

data Server = Server { sAccept :: IO Client
                     }

sshServer :: SshIdent -> RSA.PrivateKey -> RSA.PublicKey -> Server -> IO ()
sshServer v_s privKey pubKey sock = forever $
  do client <- sAccept sock
     forkIO $
       do state      <- initialState
          v_c        <- sayHello state client v_s
          (i_s, i_c) <- startKex state client
          sessionId  <- startDh client privKey pubKey state (sshDhHash v_c v_s i_c i_s)
          result     <- handleAuthentication state client sessionId

          case result of
            Nothing -> send client state
                         (SshMsgDisconnect SshDiscNoMoreAuthMethodsAvailable
                                            "" "")
            Just (_user,svc) ->
              case svc of
                SshConnection -> startConnectionService client state
                _             -> return ()

       `X.finally` cClose client

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



-- | Exchange identification information
sayHello :: SshState -> Client -> SshIdent -> IO SshIdent
sayHello state client v_s =
  do cPut client (runPutLazy (putSshIdent v_s))
     -- parseFrom used because ident doesn't use the normal framing
     msg <- parseFrom client (sshBuf state) getSshIdent
     print msg
     case msg of
       Right v_c -> return v_c
       Left err  -> fail err


supportedKex :: SshCookie -> SshKex
supportedKex cookie =
  SshKex { sshKexAlgs           = [ "diffie-hellman-group14-sha1" ]
         , sshServerHostKeyAlgs = [ "ssh-rsa" ]
         , sshEncAlgs           = SshAlgs [ "aes128-cbc" ] [ "aes128-cbc" ]
         , sshMacAlgs           = SshAlgs [ "hmac-sha1" ] [ "hmac-sha1" ]
         , sshCompAlgs          = SshAlgs [ "none" ] [ "none" ]
         , sshLanguages         = SshAlgs [] []
         , sshFirstKexFollows   = False
         , sshCookie            = cookie
         }

newCookie :: IO SshCookie
newCookie = fmap SshCookie (getRandomBytes 16)

startKex :: SshState -> Client -> IO (SshKex, SshKex)
startKex state client =
  do cookie <- newCookie
     let i_s = supportedKex cookie

     send client state (SshMsgKexInit i_s)

     i_c <- waitForClientKex
     putStrLn "Got KexInit"
     return (i_s, i_c)
  where
  waitForClientKex =
    do msg <- receive client state
       case msg of
         SshMsgKexInit i_c -> return i_c
         _                 -> waitForClientKex -- XXX What can go here?


-- |Group 2 from RFC 2409
oakley2 :: DH.Params
oakley2 = DH.Params
  { DH.params_p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF
  , DH.params_g = 2
  }

group14 :: DH.Params
group14 = DH.Params
  { DH.params_p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
  , DH.params_g = 2
  }

startDh :: Client -> RSA.PrivateKey -> RSA.PublicKey -> SshState
        -> (SshPubCert -> Integer -> Integer -> Integer -> S.ByteString)
        -> IO SshSessionId
startDh client priv pub state mkHash =
  do SshMsgKexDhInit e <- receive client state
     let hardcoded      = group14
     y <- DH.generatePrivate hardcoded
     let DH.PublicNumber f = DH.calculatePublic hardcoded y
         DH.SharedKey k = DH.getShared hardcoded y (DH.PublicNumber e)
         cert           = SshPubRsa (RSA.public_e pub) (RSA.public_n pub)
         hash           = mkHash cert e f k
         h              = convert (Hash.hashWith Hash.SHA1 hash)
         session_id     = SshSessionId h
         keys           = genKeys (convert . Hash.hashWith Hash.SHA1) k h session_id

     -- Uses IO to generate blinder
     Right sig <- RSA.signSafer (Just Hash.SHA1) priv h

     putStrLn "Sending DH reply"
     send client state (SshMsgKexDhReply cert f (SshSigRsa sig))

     putStrLn "Waiting for response"
     SshMsgNewKeys <- receive client state
     send client state SshMsgNewKeys
     transitionKeys keys state
     return session_id


handleAuthentication ::
  SshState -> Client -> SshSessionId -> IO (Maybe (S.ByteString, SshService))
handleAuthentication state client session_id =
  do let notAvailable = send client state
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
