{-# LANGUAGE CPP #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.SSH.Server (
    Server(..)
  , ServerCredential
  , SessionEvent(..)
  , sshServer
  , sayHello

  -- * Authentication and request handling.
  , AuthResult(..)
  , HandleLike(..)
  , SessionHandlers(..)
  , SshAlgs(..)
  , SshAuthMethod(..)
  , SshProposalPrefs(..)
  , SshService(..)
  , defaultAuthHandler
  , defaultCheckPw
  , defaultSessionHandlers
  , defaultLookupPubKeys
  , handle2HandleLike

  -- * RSA keys.
  , generateRsaKeyPair
  , loadPrivateKeys
  , readRsaKeyPair
  , showRsaKeyPair
  ) where

import           Network.SSH.Connection
import           Network.SSH.LoadKeys
import           Network.SSH.Messages
import           Network.SSH.Named
import           Network.SSH.Packet
import           Network.SSH.PubKey
import           Network.SSH.Rekey
import           Network.SSH.State

import           Control.Concurrent
import qualified Control.Exception as X
import           Control.Monad (forever)
import           Crypto.Hash (SHA256(..), hashWith)
import qualified Data.ByteString.Char8 as S
import           Data.IORef (writeIORef, readIORef)
import           Data.Serialize (runPutLazy)

#if !MIN_VERSION_base(4,8,0)
import Control.Applicative ((<$>))
#endif

-- Public API ------------------------------------------------------------------

data Server = Server
  { sAccept :: IO (SessionHandlers, HandleLike)
  , sAuthenticationAlgs :: [ServerCredential]
    -- | This version string should not include the leading
    -- "SSH-2.0-", which specifies the SSH protocol version; this is
    -- just the software version, e.g. "OpenSSH_6.9p1".
  , sVersion :: String
    -- | Debug level greater than zero means show debug messages.
  , sDebugLevel :: Int
  }

sshServer :: Server -> IO ()
sshServer sock = forever $
  do (sh, h) <- sAccept sock
     let handleClient = do
          let creds = sAuthenticationAlgs sock
          let prefs = allAlgsSshProposalPrefs
                { sshServerHostKeyAlgsPrefs = map nameOf creds }
          state <- initialState (sDebugLevel sock) prefs ServerRole creds
          let v_s = sshIdent $ S.pack $ sVersion sock
          v_c <- sayHello state h v_s
          writeIORef (sshIdents state) (v_s,v_c)
          initialKeyExchange h state
          -- Connection established!

          (_user, svc) <- handleAuthentication state sh h
          case svc of
            SshConnection -> runConnection sh h state connectionService
            _             -> return ()
     let handleDisconnectException SshMsgDisconnectException{..} = do
           debug' $ "client disconnected: "++show smdeReason
         -- I don't think we need to worry about cleaning up channels,
         -- since the entire SSH state for the client is about to go
         -- out of scope when this thread dies.
     let cleanup = do
           debug' "main loop exiting, closing client connection"
           -- TODO: add back @cClose h@.
     forkIO $ (handleClient `X.catch` handleDisconnectException)
              `X.finally` cleanup
  where
    -- Can't use 'Network.SSH.State.debug' here, since we don't have
    -- the 'state'.
    debug' msg = debugWithLevel (sDebugLevel sock) msg

-- | Exchange identification information
sayHello :: SshState -> HandleLike -> SshIdent -> IO SshIdent
sayHello state h v_us =
  do cPut h (runPutLazy $ putSshIdent v_us)
     -- parseFrom used because ident doesn't use the normal framing
     v_them <- parseFrom h (sshBuf state) getSshIdent
     debug state $ "their SSH version: " ++ S.unpack (sshIdentString v_them)
     return v_them

----------------------------------------------------------------
-- * Auth helpers
--
-- These auth helpers can be used to construct 'cAuthHandler' used to
-- override the default in 'Network.SSH.State.defaultSessionHandlers'.

-- | Helper for constructing the 'cAuthHandler' field of
-- 'SessionHandlers'.
--
-- The 'defaultCheckPw' and 'defaultLookupPubKeys' below can be used
-- to supply the @checkPw@ and @lookupPubKeys@ arguments. The other
-- arguments will be supplied by the auth handler later when
-- authenticating a user.
defaultAuthHandler ::
  (S.ByteString -> S.ByteString -> IO Bool) ->
  (S.ByteString -> IO [SshPubCert]) ->
  SshSessionId -> S.ByteString -> SshService -> SshAuthMethod -> IO AuthResult
defaultAuthHandler checkPw lookupPubKeys
  session_id user service authMethod = do
  case authMethod of
    -- For public key logins, a request without a signature means the
    -- user is querying if logging in is supported with a given key
    -- and algorithm, and a request with a signature is an actual
    -- login request.
    SshAuthPublicKey alg key Nothing    -> return (AuthPkOk alg key)
    SshAuthPublicKey alg key (Just sig) -> toAuth <$> checkKey alg key sig
    SshAuthPassword password Nothing    -> toAuth <$> checkPw user password
    -- One of the requests we reject here is a the two argument
    -- password request, which is a password-change request.
    _ -> return (AuthFailed ["password","publickey"] False)
  where
  toAuth True  = AuthAccepted
  toAuth False = AuthFailed ["password","publickey"] False

  checkKey alg key sig = do
    pubs <- lookupPubKeys user
    return $
      key `elem` pubs &&
      verifyPubKeyAuthentication session_id user service alg key sig

-- | Helper for constructing @checkPw@ argument to 'defaultAuthHandler'.
--
-- A "real" server probably does not store user passwords in plain
-- text ...
defaultCheckPw ::
  (S.ByteString -> Maybe S.ByteString) ->
  S.ByteString -> S.ByteString -> IO Bool
defaultCheckPw userToPw user password = do
  case userToPw user of
    Nothing -> return False
    Just password' -> do
      -- Hash passwords before comparing to avoid timing attacks.
      let hash  = hashWith SHA256 password
      let hash' = hashWith SHA256 password'
      return $ hash == hash'

-- | Helper for constructing the @lookupPubKeys@ argument to
-- 'defaultAuthHandler'.
defaultLookupPubKeys ::
  (S.ByteString -> IO [FilePath]) ->
  S.ByteString -> IO [SshPubCert]
defaultLookupPubKeys lookupPubKeyFiles user = do
  keyFiles <- lookupPubKeyFiles user
  concat <$> mapM loadPublicKeys keyFiles

----------------------------------------------------------------

handleAuthentication ::
  SshState -> SessionHandlers -> HandleLike ->
  IO (S.ByteString, SshService)
handleAuthentication state sh h =
  do let notAvailable = do
           send h state $
             SshMsgDisconnect SshDiscServiceNotAvailable
               "(Service not available)" ""
           fail "Client requested unavailable service during auth."

     Just session_id <- readIORef (sshSessionId state)
     req <- receive h state
     case req of

       SshMsgServiceRequest SshUserAuth ->
         do send h state (SshMsgServiceAccept SshUserAuth)
            authLoop

        where
         -- The auth loop runs until auth succeeds. An OpenSSH client
         -- will close the connection after receiving a
         -- 'SshMsgUserAuthFailure [] False' message, but other
         -- clients may need to be explicitly kicked by closing the
         -- connection. This connection closing is up to the
         -- 'cAuthHandler'.
         authLoop :: IO (S.ByteString, SshService)
         authLoop =
           do userReq <- receive h state
              case userReq of

                SshMsgUserAuthRequest user svc method ->
                  do result <- cAuthHandler sh session_id user svc method

                     case result of

                       AuthAccepted ->
                         do send h state SshMsgUserAuthSuccess
                            return (user, svc)

                       AuthPkOk keyAlg key ->
                         do send h state
                              (SshMsgUserAuthPkOk keyAlg key)
                            authLoop

                       -- Although it might make sense to disconnect
                       -- the client when the auth fails and there are
                       -- no methods to continue, OpenSSH does not do
                       -- this. So, we don't either, in order to get
                       -- consistent behavior when connecting to our
                       -- server with an OpenSSH client.
                       --
                       -- Note that the SSH spec allows a client to
                       -- try authenticating with a second username
                       -- after failing to authenticate with a first
                       -- username, and so on.
                       AuthFailed ms ps ->
                         do send h state (SshMsgUserAuthFailure ms ps)
                            authLoop

                _ -> notAvailable

       _ -> notAvailable
