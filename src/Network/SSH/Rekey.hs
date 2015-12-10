{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
module Network.SSH.Rekey where

import Network.SSH.Named
import Network.SSH.Mac
import Network.SSH.Ciphers
import Network.SSH.Compression
import Network.SSH.Messages
import Network.SSH.Keys
import Network.SSH.PubKey
import Network.SSH.State
import Network.SSH.Packet

import Control.Applicative ((<|>))
import Control.Monad (when)
import Data.List (find)
import Data.IORef (readIORef, modifyIORef')
import Control.Concurrent
import Control.Monad

import Data.ByteString.Short (ShortByteString)
import qualified Data.ByteString as S
import qualified Data.ByteString.Lazy as L

----------------------------------------------------------------
-- Key exchange is described in RFC 4253 sections 7 through 9

-- | Initial entry point into the rekeying logic. This version
-- sends a proposal and waits for the response.
initialKeyExchange :: Client -> SshState -> IO ()
initialKeyExchange client state =
  do let authMethods = map nameOf (sshAuthMethods state)
     i_s <- sendProposal authMethods client state
     SshMsgKexInit i_c <- receive client state
     rekeyConnection_s client state i_s i_c

initialKeyExchange_c :: Client -> SshState -> IO ()
initialKeyExchange_c client state =
  do let authMethods = ["ssh-dss", "ssh-rsa"] -- RFC 4253 Section 6.6
     i_c <- sendProposal authMethods client state
     SshMsgKexInit i_s <- receive client state
     rekeyConnection_c client state i_s i_c

-- | Subsequent entry point into the rekeying logic. This version
-- is called when a proposal has already been received and only
-- sends the response.
rekeyKeyExchange :: Client -> SshState -> SshProposal -> IO ()
rekeyKeyExchange client state i_c =
  -- TODO(conathan): bug! Make role agnostic by merging with
  -- 'initialKeyExchange'; the only difference is whether we've
  -- already received the 'SshMsgKexInit'.
  --
  -- This is called by connection handling code.
  do let authMethods = map nameOf (sshAuthMethods state)
     debug' "using server-specific auth methods!"
     i_s <- sendProposal authMethods client state
     rekeyConnection_s client state i_s i_c

sendProposal :: [ShortByteString] -> Client -> SshState -> IO SshProposal
sendProposal authMethods client state =
  do cookie <- newCookie
     let i_us = supportedKex authMethods cookie
     debug' $ "auth methods: " ++ show authMethods
     send client state (SshMsgKexInit i_us)
     return i_us

dieGracefullyOnSuiteFailure :: Client -> SshState -> Maybe CipherSuite -> IO CipherSuite
dieGracefullyOnSuiteFailure client state Nothing = do
  send client state (SshMsgDisconnect SshDiscProtocolError
                       "Failed to agree on cipher suite!" "")
  fail "cipher suite negotiation failed"
dieGracefullyOnSuiteFailure _ _ (Just cs) = return cs

rekeyConnection_s :: Client -> SshState -> SshProposal -> SshProposal -> IO ()
rekeyConnection_s client state i_s i_c =
  do (v_s, v_c) <- readIORef (sshIdents state)
     let sAuth = sshAuthMethods state

     suite <- dieGracefullyOnSuiteFailure client state
            $ computeSuite state sAuth i_s i_c
     debug' $ "server: computed suite:"
     debug' $ show (suite_desc suite)

     handleMissedGuess client state i_s i_c

     SshMsgKexDhInit pub_c <- receive client state
     (pub_s, kexFinish)    <- kexRun (suite_kex suite)
     k <- maybe (fail "bad remote public") return (kexFinish pub_c)

     let sid = SshSessionId
             $ kexHash (suite_kex suite)
             $ sshDhHash v_c v_s i_c i_s (suite_host_pub suite) pub_c pub_s k

     -- the session id doesn't change on rekeying
     modifyIORef' (sshSessionId state) (<|> Just sid)

     sig <- signSessionId (suite_host_priv suite) sid
     send client state (SshMsgKexDhReply (suite_host_pub suite) pub_s sig)

     installSecurity client state suite sid k

-- | When the client's proposal says that a kex guess packet
-- is coming, but the guess was wrong, we must drop the next
-- packet.
handleMissedGuess ::
  Client -> SshState ->
  SshProposal {- ^ server -} ->
  SshProposal {- ^ client -} ->
  IO ()
handleMissedGuess client state i_s i_c
  | sshFirstKexFollows i_c
  , kex:_ <- sshKexAlgs i_c
  , kex `notElem` sshKexAlgs i_s = void (receive client state)

  | otherwise = return ()


debug' s = putStrLn $ "debug: " ++ s

rekeyConnection_c :: Client -> SshState -> SshProposal -> SshProposal -> IO ()
rekeyConnection_c client state i_s i_c =
  do (v_s, v_c) <- readIORef (sshIdents state)
     debug' "negotiating suite in client..."
     suite <- dieGracefullyOnSuiteFailure client state
            $ computeSuite state [] i_s i_c
     debug' "negotiated suite:"
     debug' $ show (suite_desc suite)

     -- TODO(conathan): need to add a 'handleMissedGuess' here from
     -- client's point of view.

     debug' "computed suite!"
     let kex = suite_kex suite
     (pub_c, kexFinish) <- kexRun kex
     debug' "ran kex! sending dhInit to server ..."
     send client state (SshMsgKexDhInit pub_c)
     debug' "sent dhInit to server! waiting for dhReply ..."
     SshMsgKexDhReply pub_cert_s pub_s sig_s <-
       receiveSpecific SshMsgTagKexDhReply client state
     debug' "got dhReply from server!"
     k <- maybe (fail "bad remote public") return (kexFinish pub_s)
     let sid = SshSessionId
             $ kexHash kex
             $ sshDhHash v_c v_s i_c i_s pub_cert_s pub_c pub_s k

     -- the session id doesn't change on rekeying
     modifyIORef' (sshSessionId state) (<|> Just sid)
     debug' "verifying server sig ..."
     when (not $ verifyServerSig pub_cert_s sig_s sid) $ do
       send client state (SshMsgDisconnect SshDiscKexFailed
                            "Unable to verify server sig!" "")
       fail "Unable to verify server sig!"
     debug' "verified server sig!"

     installSecurity client state suite sid k

installSecurity ::
  Client -> SshState -> CipherSuite ->
  SshSessionId ->
  S.ByteString {- ^ shared secret -} ->
  IO ()
installSecurity client state suite sid k =
  do Just osid <- readIORef (sshSessionId state)
     let keys = genKeys (kexHash (suite_kex suite)) k sid osid

     send client state SshMsgNewKeys
     transitionKeysOutgoing suite keys state

     SshMsgNewKeys <- receiveSpecific SshMsgTagNewKeys client state
     transitionKeysIncoming suite keys state

transitionKeysOutgoing :: CipherSuite -> Keys -> SshState -> IO ()
transitionKeysOutgoing CipherSuite{..} Keys{..} SshState{..} =
  do compress <- makeCompress $ cs suite_c2s_comp suite_s2c_comp
     modifyMVar_ sshSendState $ \(seqNum,_,_,_,_,drg) ->
       return ( seqNum
              , cs suite_c2s_cipher suite_s2c_cipher
              , activateCipherE
                  (cs k_c2s_cipherKeys k_s2c_cipherKeys)
                  (cs suite_c2s_cipher suite_s2c_cipher)
              , cs (suite_c2s_mac k_c2s_integKey) (suite_s2c_mac k_s2c_integKey)
              , compress
              , drg
              )
  where cs = clientAndServer2us sshRole

transitionKeysIncoming :: CipherSuite -> Keys -> SshState -> IO ()
transitionKeysIncoming CipherSuite{..} Keys{..} SshState{..} =
  do decompress <- makeDecompress $ cs suite_s2c_comp suite_c2s_comp
     modifyIORef' sshRecvState $ \(seqNum, _, _, _, _) ->
       ( seqNum
       , cs suite_s2c_cipher suite_c2s_cipher
       , activateCipherD
           (cs k_s2c_cipherKeys k_c2s_cipherKeys)
           (cs suite_s2c_cipher suite_c2s_cipher)
       , cs (suite_s2c_mac k_s2c_integKey) (suite_c2s_mac k_c2s_integKey)
       , decompress
       )
  where cs = clientAndServer2us sshRole

-- TODO(conathan): refactor: remove the host private key and the host
-- public key -- these can be part of client or server specific state
-- -- and change callers to use a 'role'-based selector for c2s and
-- s2c, since these are always in the same order in the suite.
data CipherSuite = CipherSuite
  { suite_kex :: Kex
  , suite_c2s_cipher, suite_s2c_cipher :: Cipher
  , suite_c2s_mac   , suite_s2c_mac    :: L.ByteString -> Mac
  , suite_c2s_comp  , suite_s2c_comp   :: Compression
  , suite_host_priv :: PrivateKey
  , suite_host_pub  :: SshPubCert
  , suite_desc      :: CipherSuiteDesc
  }

data CipherSuiteDesc = CipherSuiteDesc
  { suite_kex_desc
  , suite_c2s_cipher_desc, suite_s2c_cipher_desc
  , suite_c2s_mac_desc   , suite_s2c_mac_desc
  , suite_c2s_comp_desc  , suite_s2c_comp_desc :: ShortByteString
  } deriving (Show)

-- | Compute a cipher suite given two proposals. The first algorithm
-- requested by the client that the server also supports is selected.
computeSuite :: SshState -> [ServerCredential] -> SshProposal -> SshProposal ->
  Maybe CipherSuite
computeSuite SshState{..} auths server client =
  do let det = determineAlg server client

     suite_kex_desc <- det sshKexAlgs
     suite_kex      <- lookupNamed allKex suite_kex_desc

     suite_c2s_cipher_desc <- det (sshClientToServer.sshEncAlgs)
     suite_c2s_cipher      <- lookupNamed allCipher suite_c2s_cipher_desc

     suite_s2c_cipher_desc <- det (sshServerToClient.sshEncAlgs)
     suite_s2c_cipher      <- lookupNamed allCipher suite_s2c_cipher_desc

     suite_c2s_mac_desc <- if aeadMode suite_c2s_cipher
                           then Just (nameOf mac_none)
                           else det (sshClientToServer.sshMacAlgs)
     suite_c2s_mac      <- lookupNamed allMac suite_c2s_mac_desc

     suite_s2c_mac_desc <- if aeadMode suite_s2c_cipher
                           then Just (nameOf mac_none)
                           else det (sshServerToClient.sshMacAlgs)
     suite_s2c_mac      <- lookupNamed allMac suite_s2c_mac_desc

     -- TODO(conathan): factor out server private key since it doesn't
     -- make sense for client.
     let host_auth_s = lookupNamed auths =<< det sshServerHostKeyAlgs
     let host_auth_c = return (undefined, undefined)
     (suite_host_pub, suite_host_priv) <- clientAndServer2us sshRole
                                          host_auth_c host_auth_s

     suite_s2c_comp_desc <- det (sshServerToClient.sshCompAlgs)
     suite_s2c_comp      <- lookupNamed allCompression suite_s2c_comp_desc

     suite_c2s_comp_desc <- det (sshClientToServer.sshCompAlgs)
     suite_c2s_comp      <- lookupNamed allCompression suite_c2s_comp_desc

     let suite_desc = CipherSuiteDesc{..}
     return CipherSuite{..}

-- | Select first client choice acceptable to the server
determineAlg ::
  SshProposal {- ^ server -} ->
  SshProposal {- ^ client -} ->
  (SshProposal -> [ShortByteString]) {- ^ selector -} ->
  Maybe ShortByteString
determineAlg server client f = find (`elem` f server) (f client)

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
