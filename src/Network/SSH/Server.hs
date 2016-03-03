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
  , Client(..)
  , defaultAuthHandler
  , defaultCheckPw
  , defaultClient
  , defaultLookupPubKeys

  -- * RSA keys.
  , generateRsaKeyPair
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
import           Control.Monad (forever, when)
import           Crypto.Hash (SHA256(..), hashWith)
import qualified Data.ByteString.Char8 as S
import           Data.IORef (writeIORef, readIORef)
import           Data.Serialize (runPutLazy)

#if !MIN_VERSION_base(4,8,0)
import Control.Applicative ((<$>))
#endif

-- Public API ------------------------------------------------------------------

data Server = Server
  { sAccept :: IO Client
  , sAuthenticationAlgs :: [ServerCredential]
  , sIdent :: SshIdent
    -- | Debug level greater than zero means show debug messages.
  , sDebugLevel :: Int
  }

sshServer :: Server -> IO ()
sshServer sock = forever $
  do client <- sAccept sock

     forkIO $
       do let creds = sAuthenticationAlgs sock
          let prefs = allAlgsSshProposalPrefs
                { sshServerHostKeyAlgsPrefs = map nameOf creds }
          state <- initialState (sDebugLevel sock) prefs ServerRole creds
          let v_s = sIdent sock
          v_c <- sayHello state client v_s
          writeIORef (sshIdents state) (v_s,v_c)
          initialKeyExchange client state
          -- Connection established!

          (_user, svc) <- handleAuthentication state client
          case svc of
            SshConnection -> runConnection client state connectionService
            _             -> return ()

       `X.finally` (do
         -- Can't use 'Network.SSH.State.debug' here, since we don't
         -- have the 'state'.
         when (sDebugLevel sock > 0) $
           putStrLn "debug: main loop caught exception, closing client..."
         cClose client)


-- | Exchange identification information
sayHello :: SshState -> Client -> SshIdent -> IO SshIdent
sayHello state client v_us =
  do cPut client (runPutLazy $ putSshIdent v_us)
     -- parseFrom used because ident doesn't use the normal framing
     v_them <- parseFrom client (sshBuf state) getSshIdent
     debug state $ "their SSH version: " ++ S.unpack (sshIdentString v_them)
     return v_them

----------------------------------------------------------------
-- * Auth helpers
--
-- These auth helpers can be used to construct 'cAuthHandler' used to
-- override the default in (the poorly named)
-- 'Network.SSH.State.defaultClient'.

-- | Helper for constructing the 'cAuthHandler' field of 'Client'.
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
    _ -> return (AuthFailed ["password","publickey"])
  where
  toAuth True  = AuthAccepted
  toAuth False = AuthFailed ["password","publickey"]

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
  SshState -> Client -> IO (S.ByteString, SshService)
handleAuthentication state client =
  do let notAvailable = do
           send client state $
             SshMsgDisconnect SshDiscServiceNotAvailable
               "(Service not available)" ""
           fail "Client requested unavailable service during auth."

     Just session_id <- readIORef (sshSessionId state)
     req <- receive client state
     case req of

       SshMsgServiceRequest SshUserAuth ->
         do send client state (SshMsgServiceAccept SshUserAuth)
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
           do userReq <- receive client state
              case userReq of

                SshMsgUserAuthRequest user svc method ->
                  do result <- cAuthHandler client session_id user svc method

                     case result of

                       AuthAccepted ->
                         do send client state SshMsgUserAuthSuccess
                            return (user, svc)

                       AuthPkOk keyAlg key ->
                         do send client state
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
                       AuthFailed ms ->
                         do send client state (SshMsgUserAuthFailure ms False)
                            authLoop

                _ -> notAvailable

       _ -> notAvailable
