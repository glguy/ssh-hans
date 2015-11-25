{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.SSH.Server (

    Server(..)
  , ServerCredential
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
import           Crypto.Random (getRandomBytes)
import qualified Data.ByteString.Char8 as S
import           Data.List (find)
import           Data.IORef
                     ( writeIORef, modifyIORef )
import           Data.Serialize
                     ( runPutLazy )

c2s_cipher = chacha20_poly1305 -- cipher_aes128_gcm
c2s_mac    = const mac_none

s2c_cipher = chacha20_poly1305 -- cipher_aes128_gcm
s2c_mac    = const mac_none -- mac_hmac_sha2_512

-- Public API ------------------------------------------------------------------

type ServerCredential =
  (S.ByteString, (SshPubCert -> S.ByteString) -> IO (SshSig, SshPubCert, S.ByteString))

data Server = Server
  { sAccept :: IO Client
  , sAuthenticationAlgs :: [ServerCredential]
  , sKeyExchange :: Kex
  , sIdent :: SshIdent
  }

sshServer :: Server -> IO ()
sshServer sock = forever $
  do client <- sAccept sock

     forkIO $
       do state             <- initialState
          let v_s            = sIdent sock
              kex            = sKeyExchange sock
          v_c               <- sayHello state client v_s
          (i_s, i_c)        <- startKex state client kex (map fst (sAuthenticationAlgs sock))
          (pub_c, pub_s, k) <- startDh client state kex

          hostKeyAlg <- case determineAlg sshServerHostKeyAlgs i_s i_c of
                          Just alg -> return alg
                          Nothing  -> fail "No host key algorithm selected"
          (sig, cert, token) <-
            case lookup hostKeyAlg (sAuthenticationAlgs sock) of
              Nothing -> fail "Bad host key algorithm selected"
              Just f -> f $ \ cert -> kexHash kex
                                    $ sshDhHash v_c v_s i_c i_s cert pub_c pub_s k

          finishDh client state sig cert pub_s
          installSecurity client state kex token k

          -- Connection established!

          result <- handleAuthentication state client (SshSessionId token)
          case result of
            Nothing -> send client state
                         (SshMsgDisconnect SshDiscNoMoreAuthMethodsAvailable
                                            "" "")
            Just (_user,svc) ->
              case svc of
                SshConnection -> startConnectionService client state
                _             -> return ()

       `X.finally` cClose client

-- | Select first client choice acceptable to the server
determineAlg ::
  (SshKex -> [S.ByteString]) {- ^ selector -} ->
  SshKex {- ^ server -} ->
  SshKex {- ^ client -} ->
  Maybe S.ByteString
determineAlg f server client = find (`elem` f server) (f client)

-- | Install new keys (and algorithms) into the SshState.
transitionKeys :: Keys -> SshState -> IO ()
transitionKeys Keys { .. } SshState { .. } =

  do modifyIORef sshRecvState $ \(seqNum, _, _) ->
               ( seqNum
               , c2s_cipher k_c2s_cipherKeys
               , c2s_mac    k_c2s_integKey)

     modifyMVar_ sshSendState $ \(seqNum,_,_) ->
        return ( seqNum
               , s2c_cipher k_s2c_cipherKeys
               , s2c_mac    k_s2c_integKey
               )

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

nullKeys :: CipherKeys
nullKeys = CipherKeys "" ""

supportedKex :: Kex -> [S.ByteString] -> SshCookie -> SshKex
supportedKex kex hostKeyAlgs cookie =
  SshKex
    { sshKexAlgs           = [ kexName kex ]
    , sshServerHostKeyAlgs = hostKeyAlgs
    , sshEncAlgs           = SshAlgs [ cipherName (c2s_cipher nullKeys)] [ cipherName (s2c_cipher nullKeys)]
    , sshMacAlgs           = SshAlgs [ mName (c2s_mac "") ] [ mName (s2c_mac "")]
    , sshCompAlgs          = SshAlgs [ "none" ] [ "none" ]
    , sshLanguages         = SshAlgs [] []
    , sshFirstKexFollows   = False
    , sshCookie            = cookie
    }

newCookie :: IO SshCookie
newCookie = fmap SshCookie (getRandomBytes 16)

startKex :: SshState -> Client -> Kex -> [S.ByteString] -> IO (SshKex, SshKex)
startKex state client kex hostKeyAlgs =
  do cookie <- newCookie
     let i_s = supportedKex kex hostKeyAlgs cookie

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

startDh :: Client -> SshState -> Kex
        -> IO (S.ByteString, S.ByteString, S.ByteString)
           {- ^ client public, server public, shared secret -}
startDh client state kex =
  do SshMsgKexDhInit pub_c <- receive client state
     (pub_s, k) <- kexRun kex pub_c
     return (pub_c, pub_s, k)

finishDh ::
  Client -> SshState ->
  SshSig -> SshPubCert ->
  S.ByteString {- ^ public dh -} ->
  IO ()
finishDh client state sig cert pub_s =
  do putStrLn "Sending DH reply"
     send client state (SshMsgKexDhReply cert pub_s sig)


installSecurity ::
  Client -> SshState -> Kex ->
  S.ByteString {- ^ sign this -} ->
  S.ByteString {- ^ shared secret -} ->
  IO ()
installSecurity client state kex token k =
  do putStrLn "Waiting for response"
     SshMsgNewKeys <- receive client state
     send client state SshMsgNewKeys
     let keys = genKeys (kexHash kex) k token
     transitionKeys keys state


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
