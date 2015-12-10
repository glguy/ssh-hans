{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.SSH.Client (
    ServerCredential
  , Client(..)
  , ClientState(..)
  , SessionEvent(..)
  , AuthResult(..)
  , sshClient
  ) where

import           Network.SSH.Connection
import           Network.SSH.Messages
import           Network.SSH.Named
import           Network.SSH.Packet
import           Network.SSH.PrivateKeyFormat
import           Network.SSH.PubKey
import           Network.SSH.Rekey
import           Network.SSH.State

import           Control.Concurrent
import qualified Control.Exception as X
import           Control.Monad ( forever, when )
import qualified Data.ByteString.Char8 as S
import qualified Data.ByteString.Lazy as L
import           Data.IORef ( writeIORef, readIORef )
import           Data.Monoid ( (<>) )
import           Data.Serialize ( runPutLazy )
import           System.Exit ( die )

-- Public API ------------------------------------------------------------------

{-
data Server = Server
  { sAccept :: IO Client
  , sAuthenticationAlgs :: [ServerCredential]
  , sIdent :: SshIdent
  }
-}

debug s = putStrLn $ "debug: " ++ s

data ClientState = ClientState
  { csIdent  :: SshIdent
  , csNet    :: Client
  , csUser   :: S.ByteString
  , csGetPw  :: IO S.ByteString
  }

sshClient :: ClientState -> IO ()
sshClient clientSt = do
  -- The '[]' is "server credentials", i.e. server private keys; we
  -- might want client keys here?
  state <- initialState ClientRole []
  let v_c = csIdent clientSt
  let client = csNet clientSt
  v_s <- sayHello state client v_c
  debug $ "server version: " ++ show v_s
  writeIORef (sshIdents state) (v_s,v_c)

  debug "starting key exchange ..."
  initialKeyExchange_c client state
  debug "key exchange done!"

  debug "starting auth ..."
  authenticate state clientSt client
  debug "auth done!"

-- TODO(conathan): factor out: duplicated from Network.ssh.server.
-- | Exchange identification information
sayHello :: SshState -> Client -> SshIdent -> IO SshIdent
sayHello state client v_c =
  do cPut client (runPutLazy $ putSshIdent v_c)
     -- parseFrom used because ident doesn't use the normal framing
     parseFrom client (sshBuf state) getSshIdent

authenticate :: SshState -> ClientState -> Client -> IO ()
authenticate state clientSt client = do
  debug "requesting ssh-userauth service from server ..."
  send client state (SshMsgServiceRequest SshUserAuth)
  SshMsgServiceAccept service <-
    receiveSpecific SshMsgTagServiceAccept client state
  when (service /= SshUserAuth) $
    send client state $
      SshMsgDisconnect SshDiscProtocolError
        "unexpected service, expected 'ssh-userauth'!" ""
  debug "server accepted ssh-userauth service request!"
  
  let user = csUser clientSt
  let svc  = SshConnection
  -- let svc  = SshServiceOther "no-such-service@galois.com"
  debug $ "attempting to log in as \"" ++ S.unpack user ++ "\" ..."

  debug "attempting password ..."
  pw <- csGetPw clientSt
  send client state
    (SshMsgUserAuthRequest user svc
      (SshAuthPassword pw Nothing))
  response <- receive client state
  case response of
    SshMsgUserAuthSuccess -> die "successfully logged in using pw!"
    SshMsgUserAuthFailure methods partialSuccess
      | null methods
      , not partialSuccess -> die "could not log in!"
      | otherwise          -> debug $
          "password login failed! can continue with: " ++ show methods
  die "TODO(conathan): authenticate using password or publickey"

{-
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
-}
