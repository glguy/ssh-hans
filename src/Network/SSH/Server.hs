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
import           Network.SSH.Compression
import           Network.SSH.Keys
import           Network.SSH.Mac
import           Network.SSH.Messages
import           Network.SSH.Named
import           Network.SSH.Packet
import           Network.SSH.PubKey
import           Network.SSH.State

import           Control.Concurrent
import           Control.Monad (forever)
import qualified Control.Exception as X
import           Data.ByteString.Short (ShortByteString)
import qualified Data.ByteString.Char8 as S
import qualified Data.ByteString.Lazy as L
import           Data.List (find)
import           Data.Monoid ((<>))
import           Data.IORef ( modifyIORef )

-- Public API ------------------------------------------------------------------

type ServerCredential = Named (SshPubCert, PrivateKey)

data Server = Server
  { sAccept :: IO Client
  , sAuthenticationAlgs :: [ServerCredential]
  , sIdent :: SshIdent
  }

sshServer :: Server -> IO ()
sshServer sock = forever $
  do client <- sAccept sock

     forkIO $
       do state <- initialState
          let v_s = sIdent sock
          v_c <- sayHello state client v_s
          sessionId <- keyExchangePhase client state v_s v_c (sAuthenticationAlgs sock)

          -- Connection established!

          result <- handleAuthentication state client sessionId
          case result of
            Nothing -> send client state
                         (SshMsgDisconnect SshDiscNoMoreAuthMethodsAvailable
                                            "" "")
            Just (_user,svc) ->
              case svc of
                SshConnection -> startConnectionService client state
                _             -> return ()

       `X.finally` cClose client

keyExchangePhase ::
  Client ->
  SshState ->
  SshIdent {- ^ server -}  ->
  SshIdent {- ^ client -} ->
  [ServerCredential] ->
  IO SshSessionId {- ^ session id for client authentication -}
keyExchangePhase client state v_s v_c sAuth =
  do (i_s, i_c) <- startKex state client (map nameOf sAuth)
     suite <- maybe (fail "negotiation failed") return
            $ computeSuite sAuth i_s i_c

     SshMsgKexDhInit pub_c <- receive client state
     (pub_s, k)            <- kexRun (suite_kex suite) pub_c

     let sid = SshSessionId
             $ kexHash (suite_kex suite)
             $ sshDhHash v_c v_s i_c i_s (suite_host_pub suite) pub_c pub_s k

     sig <- sign (suite_host_priv suite) sid
     send client state (SshMsgKexDhReply (suite_host_pub suite) pub_s sig)

     installSecurity client state suite sid k
     return sid

data CipherSuite = CipherSuite
  { suite_kex :: Kex
  , suite_c2s_cipher, suite_s2c_cipher :: CipherKeys -> Cipher
  , suite_c2s_mac   , suite_s2c_mac    :: L.ByteString -> Mac
  , suite_c2s_comp  , suite_s2c_comp   :: Compression
  , suite_host_priv :: PrivateKey
  , suite_host_pub :: SshPubCert
  }

-- | Compute a cipher suite given two proposals. The first algorithm
-- requested by the client that the server also supports is selected.
computeSuite :: [ServerCredential] -> SshProposal -> SshProposal -> Maybe CipherSuite
computeSuite auths server client =
  do let det = determineAlg server client

     suite_kex        <- lookupNamed allKex =<< det sshKexAlgs

     c2s_cipher_name  <- det (sshClientToServer.sshEncAlgs)
     suite_c2s_cipher <- lookupNamed allCipher c2s_cipher_name

     s2c_cipher_name  <- det (sshServerToClient.sshEncAlgs)
     suite_s2c_cipher <- lookupNamed allCipher s2c_cipher_name

     suite_c2s_mac <- if c2s_cipher_name `elem` aeadModes
                        then Just (namedThing mac_none)
                        else lookupNamed allMac =<< det (sshClientToServer.sshMacAlgs)

     suite_s2c_mac <- if s2c_cipher_name `elem` aeadModes
                        then Just (namedThing mac_none)
                        else lookupNamed allMac =<< det (sshServerToClient.sshMacAlgs)

     (suite_host_pub, suite_host_priv) <- lookupNamed auths =<< det sshServerHostKeyAlgs

     s2c_comp_name <- det (sshServerToClient.sshCompAlgs)
     suite_s2c_comp <- lookupNamed allCompression s2c_comp_name

     c2s_comp_name <- det (sshClientToServer.sshCompAlgs)
     suite_c2s_comp <- lookupNamed allCompression c2s_comp_name

     return CipherSuite{..}

-- | Select first client choice acceptable to the server
determineAlg ::
  SshProposal {- ^ server -} ->
  SshProposal {- ^ client -} ->
  (SshProposal -> [ShortByteString]) {- ^ selector -} ->
  Maybe ShortByteString
determineAlg server client f = find (`elem` f server) (f client)

-- | Install new keys (and algorithms) into the SshState.
transitionKeysOutgoing :: CipherSuite -> Keys -> SshState -> IO ()
transitionKeysOutgoing CipherSuite{..} Keys{..} SshState{..} =
  do compress <- makeCompress suite_s2c_comp
     modifyMVar_ sshSendState $ \(seqNum,_,_,_,drg) ->
       return ( seqNum
              , suite_s2c_cipher k_s2c_cipherKeys
              , suite_s2c_mac    k_s2c_integKey
              , compress
              , drg
              )

transitionKeysIncoming :: CipherSuite -> Keys -> SshState -> IO ()
transitionKeysIncoming CipherSuite{..} Keys{..} SshState{..} =
  do decompress <- makeDecompress suite_c2s_comp
     modifyIORef sshRecvState $ \(seqNum, _, _, _) ->
       ( seqNum
       , suite_c2s_cipher k_c2s_cipherKeys
       , suite_c2s_mac    k_c2s_integKey
       , decompress
       )

-- | Exchange identification information
sayHello :: SshState -> Client -> SshIdent -> IO SshIdent
sayHello state client v_s =
  do cPut client (L.fromStrict (sshIdentString v_s <> "\r\n"))
     -- parseFrom used because ident doesn't use the normal framing
     parseFrom client (sshBuf state) getSshIdent

supportedKex :: [ShortByteString] -> SshCookie -> SshProposal
supportedKex hostKeyAlgs cookie =
  SshProposal
    { sshKexAlgs           = (map nameOf allKex)
    , sshServerHostKeyAlgs = hostKeyAlgs
    , sshEncAlgs           = SshAlgs (map nameOf allCipher) (map nameOf allCipher)
    , sshMacAlgs           = SshAlgs (map nameOf allMac) (map nameOf allMac)
    , sshCompAlgs          = SshAlgs (map nameOf allCompression) (map nameOf allCompression)
    , sshLanguages         = SshAlgs [] []
    , sshFirstKexFollows   = False
    , sshProposalCookie    = cookie
    }

startKex ::
  SshState -> Client -> [ShortByteString] ->
  IO (SshProposal, SshProposal)
startKex state client hostKeyAlgs =
  do let i_s = supportedKex hostKeyAlgs (sshCookie state)
     send client state (SshMsgKexInit i_s)
     SshMsgKexInit i_c <- receive client state
     return (i_s, i_c)

installSecurity ::
  Client -> SshState -> CipherSuite ->
  SshSessionId ->
  S.ByteString {- ^ shared secret -} ->
  IO ()
installSecurity client state suite sid k =
  do let keys = genKeys (kexHash (suite_kex suite)) k sid

     send client state SshMsgNewKeys
     transitionKeysOutgoing suite keys state

     SshMsgNewKeys <- receive client state
     transitionKeysIncoming suite keys state


handleAuthentication ::
  SshState -> Client -> SshSessionId -> IO (Maybe (S.ByteString, SshService))
handleAuthentication state client session_id =
  do let notAvailable = send client state
                      $ SshMsgDisconnect SshDiscServiceNotAvailable "" ""

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
