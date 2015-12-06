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
import Data.List (find)
import Data.IORef (readIORef, modifyIORef')
import Control.Concurrent
import Control.Monad

import Data.ByteString.Short (ShortByteString)
import qualified Data.ByteString as S
import qualified Data.ByteString.Lazy as L

-- | Initial entry point into the rekeying logic. This version
-- sends a proposal and waits for the response.
initialKeyExchange :: Client -> SshState -> IO ()
initialKeyExchange client state =
  do i_s <- sendProposal client state
     SshMsgKexInit i_c <- receive client state
     rekeyConnection client state i_s i_c


-- | Subsequent entry point into the rekeying logic. This version
-- is called when a proposal has already been received and only
-- sends the response.
rekeyKeyExchange :: Client -> SshState -> SshProposal -> IO ()
rekeyKeyExchange client state i_c =
  do i_s <- sendProposal client state
     rekeyConnection client state i_s i_c


sendProposal :: Client -> SshState -> IO SshProposal
sendProposal client state =
  do cookie <- newCookie
     let authMethods = map nameOf (sshAuthMethods state)
         i_s         = supportedKex authMethods cookie
     send client state (SshMsgKexInit i_s)
     return i_s


rekeyConnection :: Client -> SshState -> SshProposal -> SshProposal -> IO ()
rekeyConnection client state i_s i_c =
  do (v_s, v_c) <- readIORef (sshIdents state)
     let sAuth = sshAuthMethods state

     suite <- maybe (fail "negotiation failed") return
            $ computeSuite sAuth i_s i_c

     handleMissedGuess client state i_s i_c

     SshMsgKexDhInit pub_c <- receive client state
     (pub_s, kexFinish)    <- kexRun (suite_kex suite)
     k <- maybe (fail "bad remote public") return (kexFinish pub_c)

     let sid = SshSessionId
             $ kexHash (suite_kex suite)
             $ sshDhHash v_c v_s i_c i_s (suite_host_pub suite) pub_c pub_s k

     -- the session id doesn't change on rekeying
     modifyIORef' (sshSessionId state) (<|> Just sid)

     sig <- sign (suite_host_priv suite) sid
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

     SshMsgNewKeys <- receive client state
     transitionKeysIncoming suite keys state

transitionKeysOutgoing :: CipherSuite -> Keys -> SshState -> IO ()
transitionKeysOutgoing CipherSuite{..} Keys{..} SshState{..} =
  do compress <- makeCompress suite_s2c_comp
     modifyMVar_ sshSendState $ \(seqNum,_,_,_,_,drg) ->
       return ( seqNum
              , suite_s2c_cipher
              , activateCipherE k_s2c_cipherKeys suite_s2c_cipher
              , suite_s2c_mac k_s2c_integKey
              , compress
              , drg
              )

transitionKeysIncoming :: CipherSuite -> Keys -> SshState -> IO ()
transitionKeysIncoming CipherSuite{..} Keys{..} SshState{..} =
  do decompress <- makeDecompress suite_c2s_comp
     modifyIORef' sshRecvState $ \(seqNum, _, _, _, _) ->
       ( seqNum
       , suite_c2s_cipher
       , activateCipherD k_c2s_cipherKeys suite_c2s_cipher
       , suite_c2s_mac k_c2s_integKey
       , decompress
       )

data CipherSuite = CipherSuite
  { suite_kex :: Kex
  , suite_c2s_cipher, suite_s2c_cipher :: Cipher
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

     suite_c2s_cipher <- lookupNamed allCipher =<< det (sshClientToServer.sshEncAlgs)

     suite_s2c_cipher <- lookupNamed allCipher =<< det (sshServerToClient.sshEncAlgs)

     suite_c2s_mac <- if aeadMode suite_c2s_cipher
                        then Just (namedThing mac_none)
                        else lookupNamed allMac =<< det (sshClientToServer.sshMacAlgs)

     suite_s2c_mac <- if aeadMode suite_s2c_cipher
                        then Just (namedThing mac_none)
                        else lookupNamed allMac =<< det (sshServerToClient.sshMacAlgs)

     (suite_host_pub, suite_host_priv) <- lookupNamed auths =<< det sshServerHostKeyAlgs

     suite_s2c_comp <- lookupNamed allCompression =<< det (sshServerToClient.sshCompAlgs)

     suite_c2s_comp <- lookupNamed allCompression =<< det (sshClientToServer.sshCompAlgs)

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
