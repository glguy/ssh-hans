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
import           Crypto.Random (getRandomBytes)
import qualified Data.ByteString.Char8 as S
import           Data.IORef
                     ( writeIORef, modifyIORef )
import           Data.Serialize
                     ( runPutLazy )

-- Public API ------------------------------------------------------------------

data Server = Server { sAccept :: IO Client
                     }

sshServer :: SshIdent -> Kex -> RSA.PrivateKey -> RSA.PublicKey -> Server -> IO ()
sshServer v_s kex privKey pubKey sock = forever $
  do client <- sAccept sock

     forkIO $
       do state      <- initialState
          v_c        <- sayHello state client v_s
          (i_s, i_c) <- startKex state client kex
          sessionId  <- startDh client privKey pubKey state kex (sshDhHash v_c v_s i_c i_s)
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


supportedKex :: Kex -> SshCookie -> SshKex
supportedKex kex cookie =
  SshKex
    { sshKexAlgs           = [ kexName kex ]
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

startKex :: SshState -> Client -> Kex -> IO (SshKex, SshKex)
startKex state client kex =
  do cookie <- newCookie
     let i_s = supportedKex kex cookie

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

startDh :: Client -> RSA.PrivateKey -> RSA.PublicKey -> SshState
        -> Kex
        -> (SshPubCert -> S.ByteString -> S.ByteString -> S.ByteString -> S.ByteString)
        -> IO SshSessionId
startDh client priv pub state kex mkToken =
  do SshMsgKexDhInit pub_c <- receive client state

     (pub_s, k) <- kexRun kex pub_c

     let cert           = SshPubRsa (RSA.public_e pub) (RSA.public_n pub)
         token          = mkToken cert pub_c pub_s k
         h              = kexHash kex token
         session_id     = SshSessionId h
         keys           = genKeys (kexHash kex) k h session_id

     -- Uses IO to generate blinder
     Right sig <- RSA.signSafer (Just Hash.SHA1) priv h

     putStrLn "Sending DH reply"
     send client state (SshMsgKexDhReply cert pub_s (SshSigRsa sig))

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
