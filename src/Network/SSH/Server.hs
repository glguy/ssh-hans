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
import           Network.SSH.Named
import           Network.SSH.Packet
import           Network.SSH.State

import           Control.Concurrent
import           Control.Monad (forever)
import qualified Control.Exception as X
import           Crypto.Random (getRandomBytes)
import           Data.ByteString.Short (ShortByteString)
import qualified Data.ByteString.Char8 as S
import qualified Data.ByteString.Lazy as L
import           Data.List (find)
import           Data.IORef ( modifyIORef )
import           Data.Serialize ( runPutLazy )

-- Public API ------------------------------------------------------------------

type ServerCredential =
  (ShortByteString, (SshPubCert -> S.ByteString) -> IO (SshSig, SshPubCert, S.ByteString))

data Server = Server
  { sAccept :: IO Client
  , sAuthenticationAlgs :: [ServerCredential]
  , sIdent :: SshIdent
  }

sshServer :: Server -> IO ()
sshServer sock = forever $
  do client <- sAccept sock

     forkIO $
       do state             <- initialState
          let v_s            = sIdent sock
          v_c               <- sayHello state client v_s
          (i_s, i_c)        <- startKex state client (map fst (sAuthenticationAlgs sock))

          suite <- case computeSuite i_s i_c of
                     Nothing -> fail "negotiation failed"
                     Just suite -> return suite

          hostKeyAlg <- case determineAlg sshServerHostKeyAlgs i_s i_c of
                          Just alg -> return alg
                          Nothing  -> fail "No host key algorithm selected"

          (pub_c, pub_s, k) <- startDh client state (suite_kex suite)
          (sig, cert, token) <-
            case lookup hostKeyAlg (sAuthenticationAlgs sock) of
              Nothing -> fail "Bad host key algorithm selected"
              Just f -> f $ \ cert -> kexHash (suite_kex suite)
                                    $ sshDhHash v_c v_s i_c i_s cert pub_c pub_s k

          finishDh client state sig cert pub_s
          installSecurity client state suite token k

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

data CipherSuite = CipherSuite
  { suite_kex :: Kex
  , suite_c2s_cipher, suite_s2c_cipher :: CipherKeys -> Cipher
  , suite_c2s_mac   , suite_s2c_mac    :: L.ByteString -> Mac
  }

computeSuite :: SshKex -> SshKex -> Maybe CipherSuite
computeSuite server client =
  do suite_kex        <- lookupNamed allKex
                     =<< determineAlg sshKexAlgs server client

     c2s_cipher_name  <- determineAlg (sshClientToServer.sshEncAlgs) server client
     suite_c2s_cipher <- lookupNamed allCipher c2s_cipher_name

     s2c_cipher_name  <- determineAlg (sshServerToClient.sshEncAlgs) server client
     suite_s2c_cipher <- lookupNamed allCipher s2c_cipher_name

     suite_c2s_mac <- if c2s_cipher_name `elem` aeadModes
                        then Just (namedThing mac_none)
                        else lookupNamed allMac
                         =<< determineAlg (sshClientToServer.sshMacAlgs) server client

     suite_s2c_mac <- if s2c_cipher_name `elem` aeadModes
                        then Just (namedThing mac_none)
                        else lookupNamed allMac
                     =<< determineAlg (sshServerToClient.sshMacAlgs) server client

     "none" <- determineAlg (sshServerToClient.sshCompAlgs) server client
     "none" <- determineAlg (sshClientToServer.sshCompAlgs) server client

     return CipherSuite{..}

-- | Select first client choice acceptable to the server
determineAlg ::
  (SshKex -> [ShortByteString]) {- ^ selector -} ->
  SshKex {- ^ server -} ->
  SshKex {- ^ client -} ->
  Maybe ShortByteString
determineAlg f server client = find (`elem` f server) (f client)

-- | Install new keys (and algorithms) into the SshState.
transitionKeys :: CipherSuite -> Keys -> SshState -> IO ()
transitionKeys CipherSuite{..} Keys{..} SshState{..} =

  do modifyIORef sshRecvState $ \(seqNum, _, _) ->
               ( seqNum
               , suite_c2s_cipher k_c2s_cipherKeys
               , suite_c2s_mac    k_c2s_integKey
               )

     modifyMVar_ sshSendState $ \(seqNum,_,_,drg) ->
        return ( seqNum
               , suite_s2c_cipher k_s2c_cipherKeys
               , suite_s2c_mac    k_s2c_integKey
               , drg
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

supportedKex :: [ShortByteString] -> SshCookie -> SshKex
supportedKex hostKeyAlgs cookie =
  SshKex
    { sshKexAlgs           = (map nameOf allKex)
    , sshServerHostKeyAlgs = hostKeyAlgs
    , sshEncAlgs           = SshAlgs (map nameOf allCipher) (map nameOf allCipher)
    , sshMacAlgs           = SshAlgs (map nameOf allMac   ) (map nameOf allMac   )
    , sshCompAlgs          = SshAlgs [ "none" ] [ "none" ]
    , sshLanguages         = SshAlgs [] []
    , sshFirstKexFollows   = False
    , sshCookie            = cookie
    }

newCookie :: IO SshCookie
newCookie = fmap SshCookie (getRandomBytes 16)

startKex :: SshState -> Client -> [ShortByteString] -> IO (SshKex, SshKex)
startKex state client hostKeyAlgs =
  do cookie <- newCookie
     let i_s = supportedKex hostKeyAlgs cookie

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
  Client -> SshState -> CipherSuite ->
  S.ByteString {- ^ sign this -} ->
  S.ByteString {- ^ shared secret -} ->
  IO ()
installSecurity client state suite token k =
  do putStrLn "Waiting for response"
     SshMsgNewKeys <- receive client state
     send client state SshMsgNewKeys
     let keys = genKeys (kexHash (suite_kex suite)) k token
     transitionKeys suite keys state


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
