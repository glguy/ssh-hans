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

import           Network.SSH.Connection
import           Network.SSH.Messages
import           Network.SSH.Packet
import           Network.SSH.Rekey
import           Network.SSH.State

import           Control.Concurrent
import           Control.Monad (forever)
import qualified Control.Exception as X
import qualified Data.ByteString.Char8 as S
import qualified Data.ByteString.Lazy as L
import           Data.Monoid ((<>))
import           Data.IORef (writeIORef, readIORef)

-- Public API ------------------------------------------------------------------

data Server = Server
  { sAccept :: IO Client
  , sAuthenticationAlgs :: [ServerCredential]
  , sIdent :: SshIdent
  }

sshServer :: Server -> IO ()
sshServer sock = forever $
  do client <- sAccept sock

     forkIO $
       do state <- initialState (sAuthenticationAlgs sock)
          let v_s = sIdent sock
          v_c <- sayHello state client v_s
          writeIORef (sshIdents state) (v_s,v_c)
          initialKeyExchange client state

          -- Connection established!

          result <- handleAuthentication state client
          case result of
            Nothing -> send client state
                         (SshMsgDisconnect SshDiscNoMoreAuthMethodsAvailable
                                            "" "")
            Just (_user,svc) ->
              case svc of
                SshConnection -> startConnectionService client state
                _             -> return ()

       `X.finally` cClose client


-- | Exchange identification information
sayHello :: SshState -> Client -> SshIdent -> IO SshIdent
sayHello state client v_s =
  do cPut client (L.fromStrict (sshIdentString v_s <> "\r\n"))
     -- parseFrom used because ident doesn't use the normal framing
     parseFrom client (sshBuf state) getSshIdent


handleAuthentication ::
  SshState -> Client -> IO (Maybe (S.ByteString, SshService))
handleAuthentication state client =
  do let notAvailable = send client state
                      $ SshMsgDisconnect SshDiscServiceNotAvailable "" ""

     Just session_id <- readIORef (sshSessionId state)
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
