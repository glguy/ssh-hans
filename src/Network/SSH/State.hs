-- |
-- State data for one client-server pair, and many related types.

{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE BangPatterns #-}

module Network.SSH.State where


import           Network.SSH.Ciphers
import           Network.SSH.Mac
import           Network.SSH.Messages
import           Network.SSH.Named
import           Network.SSH.Packet
import           Network.SSH.PubKey (PrivateKey)
import           Network.SSH.TerminalModes

import           Control.Concurrent
import           Control.Concurrent.STM ( TChan, TVar, newTVarIO )
import           Control.Monad
import           Crypto.Random
import           Data.ByteString.Short (ShortByteString)
import qualified Data.ByteString as S
import qualified Data.ByteString.Char8 as S8
import qualified Data.ByteString.Lazy as L
import           Data.Char (isControl)
import           Data.IORef
import           Data.Map.Strict ( Map )
import qualified Data.Map.Strict as Map
import           Data.Serialize
import           Data.Word

debug :: SshState -> String -> IO ()
debug st s = do
  when (sshDebugLevel st > 0) $
    putStrLn $ "debug: " ++ s

-- Server Internals ------------------------------------------------------------

data AuthResult
  = AuthFailed [ShortByteString] Bool
    -- ^ The 'Bool' is for "partial success"; see RFC 4252 Section
    -- 5.1.
  | AuthAccepted
  | AuthPkOk S.ByteString SshPubCert
    -- ^ Returned by the server to indicate that a public key is
    -- supported for authentication; see @SSH_MSG_USERAUTH_PK_OK@ in
    -- RFC 4252 Section 7.
  deriving Show

-- We might want to split this into separate types for separate
-- classes of channel events.
data SessionEvent
  -- Data messages.
  = SessionData S.ByteString               -- Needs window size accounting.
  {-
  | SessionExtendedDataStdErr S.ByteString -- Needs window size accounting.
  -}

  -- Could be considered data or non-data.
  | SessionClose
  | SessionEof

  -- Non-data messages.
  --
  -- May also want request messages here, in addition to request
  -- responses.
  | SessionWinsize SshWindowSize
  | SessionRequestResponse Bool -- ^ True for "channel success"
                                --   and false for "channel failure".
  {-
  | SessionRequest {}
  -}

-- | A mix of connection state and session handlers.
--
-- The session backends here -- 'cOpenShell', 'cDirectTcp',
-- 'cRequestSubsystem', 'cRequestExec' -- are expected to return
-- immediately with a boolean indicating whether the requested
-- operation was allowed or not. So, implementers probably want to use
-- 'forkIO' to run session backends in a separate thread.
--
-- TODO(conathan): rename, e.g 'ClientState', since we are adding
-- client support. Or maybe, refactor this into client specific state
-- (if any; the 'cOpenShell' may be client only) and general "other
-- end of the connection state". From this symmetric point of view, it
-- might make sense to call the other end the client, but that could
-- be confusing since we also define client and server modules. Better
-- to call it something else ...
data Client = Client
  { cGet         :: Int -> IO S.ByteString
  -- ^ Read up to 'n' bytes from network socket

  -- | Put bytes on network socket
  , cPut         :: L.ByteString -> IO ()

  -- | Close network socket
  , cClose       :: IO ()

  -- | Log messages for events related to this client
  , cLog         :: String -> IO ()

  -- | TERM, initial window dimensions, termios flags, incoming events, write callback
  , cOpenShell   :: S.ByteString -> SshWindowSize -> [(TerminalFlag, Word32)] ->
                    IO SessionEvent ->
                    (Maybe S.ByteString -> IO ()) ->
                    IO Bool

  , cDirectTcp   :: S.ByteString -> Word32 ->
                    IO SessionEvent ->
                    (Maybe S.ByteString -> IO ()) ->
                    IO Bool

  -- | Client requested a subsystem. Return 'True' to accept.
  --
  -- The 'S.ByteString' argument is the subsystem requested.
  --
  -- The @IO SessionEvent@ argument is used to read events from the
  -- channel.
  --
  -- The @Maybe S.ByteString -> IO ()@ argument is used to write back
  -- to the channel: send @Just bs@ to send @bs@, and @Nothing@ to
  -- close the channel.
  --
  -- The subsystem mechanism allows for arbitrary "built in" commands
  -- in SSH. The only subsystem that ships with an OpenSSH SSH server
  -- is SFTP. An OpenSSH client requests the subsystem @<subsystem>@
  -- using the syntax @ssh <host> -s <subsystem>@. Strangely, the @-s@
  -- arg has to come *after* the host name.
  , cRequestSubsystem
                 :: S.ByteString ->
                    IO SessionEvent ->
                    (Maybe S.ByteString -> IO ()) ->
                    IO Bool

  -- | Client requested executing a command. Return True to accept.
  --
  -- See 'cRequestSubsystem' for explanation of arguments.
  --
  -- Exec requests are typically handled by running the requested
  -- command through the user's shell. An OpenSSH client makes an exec
  -- request for command @<command>@ using the syntax
  -- @ssh <host> <command>@.
  , cRequestExec :: S.ByteString ->
                    IO SessionEvent ->
                    (Maybe S.ByteString -> IO ()) ->
                    IO Bool

  -- | ByteString argument is user name
  , cAuthHandler :: SshSessionId  ->
                    S.ByteString  ->
                    SshService    ->
                    SshAuthMethod ->
                    IO AuthResult
  }

-- | Default them state.
--
-- The fields defined with 'error' always need to be overridden. The
-- other fields are unused when we're a client. When we're a server,
-- the other fields are used, but default to rejecting all requests,
-- including authentication.
defaultClient :: Client
defaultClient = Client
  { cGet   = error "cGet undefined!"
  , cPut   = error "cPut undefined!"
  , cClose = error "cClose undefined!"
  , cLog   = error "cLog undefined!"

  -- Make all requests fail immediately.
  --
  -- The empty list in 'AuthFailed []' means there are no auth methods
  -- by which the client can continue authentication. The OpenSSH
  -- client quits when receiving this.
  , cAuthHandler      = \_ _ _ _   -> return $ AuthFailed [] False
  -- These non-auth requests are only allowed after auth succeeds, and
  -- so will never be called for the default 'cAuthHandler' above.
  , cOpenShell        = \_ _ _ _ _ -> return False
  , cDirectTcp        = \_ _ _ _   -> return False
  , cRequestSubsystem = \_ _ _     -> return False
  , cRequestExec      = \_ _ _     -> return False
  }

----------------------------------------------------------------

data Role = ClientRole | ServerRole
  deriving (Eq,Show)

-- | Select our value from client and server values according to 'Role'.
--
-- Mnemonic: argument order is the same as the function name: client
-- and then server.
clientAndServer2usAndThem ::
  Role -> a {- ^ client value -} -> a {- ^ server value -} -> (a, a)
clientAndServer2usAndThem ClientRole c s = (c, s)
clientAndServer2usAndThem ServerRole c s = (s, c)

clientAndServer2us :: Role -> a -> a -> a
clientAndServer2us role c s = fst $ clientAndServer2usAndThem role c s

clientAndServer2them :: Role -> a -> a -> a
clientAndServer2them role c s = snd $ clientAndServer2usAndThem role c s


usAndThem2clientAndServer ::
  Role -> a {- ^ our value -} -> a {- ^ their value -} -> (a, a)
usAndThem2clientAndServer ClientRole us them = (us, them)
usAndThem2clientAndServer ServerRole us them = (them, us)

usAndThem2c :: Role -> a -> a -> a
usAndThem2c role us them = fst $ usAndThem2clientAndServer role us them

usAndThem2s :: Role -> a -> a -> a
usAndThem2s role us them = snd $ usAndThem2clientAndServer role us them

----------------------------------------------------------------

type CompressFun   = S.ByteString -> IO L.ByteString
type DecompressFun = S.ByteString -> IO L.ByteString
type ChannelId     = Word32

-- | State for one client-server connection / transport.
data SshState = SshState
  { sshRecvState :: !(IORef (Word32, Cipher, ActiveCipher, Mac, DecompressFun)) -- ^ Client context
  , sshBuf       :: !(IORef S.ByteString)
  , sshSendState :: !(MVar (Word32, Cipher, ActiveCipher, Mac, CompressFun, ChaChaDRG)) -- ^ Server encryption context
  , sshSessionId :: !(IORef (Maybe SshSessionId))
  , sshRole          :: Role
  , sshAuthMethods   :: [ServerCredential]
  , sshIdents        :: !(IORef (SshIdent, SshIdent)) -- server, client
  , sshProposalPrefs :: SshProposalPrefs
  -- | The channels running over this transport.
  --
  -- The outer 'TVar' protects insertion and deletion, and the inner
  -- 'TVar' protects the state of an individual channel.
  , sshChannels      :: !(TVar (Map ChannelId (TVar SshChannel)))
  , sshDebugLevel    :: !Int -- ^ Used by 'debug'.
  }

-- | Partial specification of an 'SshProposal'.
data SshProposalPrefs = SshProposalPrefs
  { sshKexAlgsPrefs           :: NameList
  , sshServerHostKeyAlgsPrefs :: NameList
  , sshEncAlgsPrefs           :: !SshAlgs
  , sshMacAlgsPrefs           :: !SshAlgs
  , sshCompAlgsPrefs          :: !SshAlgs
  } deriving (Eq,Show,Read)

type ServerCredential = Named (SshPubCert, PrivateKey)

-- TODO(conathan): factor out server credentials since they don't make
-- sense in the client.

-- | Build initial 'SshState'.
--
-- If the 'sshDebugLevel' is greater than zero then debug messages
-- will be printed.
initialState ::
  Int -> SshProposalPrefs -> Role -> [ServerCredential] -> IO SshState
initialState sshDebugLevel prefs sshRole creds =
  do drg          <- drgNew
     let none = namedThing cipher_none
     sshRecvState <- newIORef (0,none
                                ,activateCipherD_none
                                ,namedThing mac_none ""
                                ,return . L.fromStrict) -- no decompression
     sshSendState <- newMVar  (0,none
                                ,activateCipherE_none
                                ,namedThing mac_none ""
                                ,return . L.fromStrict -- no compression
                                ,drg)
     sshBuf       <- newIORef S.empty
     sshSessionId <- newIORef Nothing
     sshIdents    <- newIORef (error "idents uninitialized")
     let sshAuthMethods   = creds
     let sshProposalPrefs = prefs
     sshChannels <- newTVarIO Map.empty
     return SshState { .. }

-- | Construct a new, random cookie
newCookie :: IO SshCookie
newCookie = SshCookie `fmap` getRandomBytes 16

send :: Client -> SshState -> SshMsg -> IO ()
send client SshState { .. } msg =
  modifyMVar_ sshSendState $ \(seqNum, cipher, activeCipher, mac, comp, gen) ->
    do payload <- comp (runPut (putSshMsg msg))
       let (pkt,activeCipher',gen') = putSshPacket seqNum cipher activeCipher mac gen payload
       -- TODO(conathan): how to tell if the connection is closed
       -- here? Would like to raise an error when trying to write to a
       -- closed connection, no?
       cPut client pkt
       return (seqNum+1, cipher, activeCipher',mac, comp, gen')

-- | Like 'receive', but fail when receiving an unexpected msg.
receiveSpecific :: SshMsgTag -> Client -> SshState -> IO SshMsg
receiveSpecific tag client sshState = do
  msg <- receive client sshState
  if sshMsgTag msg == tag
  then return msg
  else fail $ "unexpected msg of type" ++ show (sshMsgTag msg)

receive :: Client -> SshState -> IO SshMsg
receive client SshState { .. } = loop
  where
  loop =
    do (seqNum, cipher, activeCipher, mac, decomp) <- readIORef sshRecvState
       (payload, activeCipher') <- parseFrom client sshBuf
                                 $ getSshPacket seqNum cipher activeCipher mac
       payload' <- decomp payload
       msg <- either fail return $ runGetLazy getSshMsg payload'
       let !seqNum1 = seqNum + 1
       writeIORef sshRecvState (seqNum1, cipher, activeCipher', mac, decomp)
       case msg of
         SshMsgIgnore _                      -> loop
         SshMsgDebug display m _ | display   -> do cLog client (filter (not . isControl)
                                                                       (S8.unpack m))
                                                   loop -- XXX drop controls
                                 | otherwise -> loop
         SshMsgDisconnect reason msg' _lang   ->
           fail $ "other end disconnected: " ++ show reason ++ ": " ++
                  S8.unpack msg'
         _                                   -> return msg

parseFrom :: Client -> IORef S.ByteString -> Get a -> IO a
parseFrom handle buffer body =
  do bytes <- readIORef buffer
     go (S.null bytes) (runGetPartial body bytes)

  where
  -- boolean: beginning of packet
  go beginning (Partial k) =
       -- If the connection gets closed the handle will still be open
       -- -- i.e. 'hIsClosed' will return false -- but reads on the
       -- handle will return the empty string.
    do bytes <- cGet handle 32752
       when (beginning && S.null bytes) (fail "Connection closed")
       go False (k bytes)

  go _ (Done a bs) =
    do writeIORef buffer bs
       return a

  go _ (Fail s _) = fail s

----------------------------------------------------------------
-- Channels

-- | Channel states.
--
-- These states were created with "session" channels in mind, and may
-- need to refined to handle other channel types. For example,
-- requesting a session backend on a non-session channel does not make
-- sense.
data SshChannelState
  = SshChannelStateOpenRequested    -- ^ Open request sent.
  | SshChannelStateOpenFailed SshOpenFailure S.ByteString S.ByteString
                                    -- ^ Open request sent and rejection received.
  | SshChannelStateOpen             -- ^ Open confirmation received or sent. We also enter
                                    --   this state from "backend requested" if the backend
                                    --   request fails.
  | SshChannelStateBackendRequested -- ^ Backend ("shell", "exec", or "subsystem")
                                    --   request sent
  | SshChannelStateBackendRunning   -- ^ Backend request confirmation received.
  deriving (Eq, Show)
{-
  | SshChannelStateCloseSent        -- ^ A channel close has been sent.
  | SshChannelStateClosed           -- ^ A channel close has been received.
-}
-- | SshChannelStateError

-- | The state of an SSH Channel.
--
-- Channel state is updated atomically, by manipulating 'TVar
-- SshChannel's in the 'sshChannels' map in the 'SshState'. A channel
-- also has an channel id for us, but that is stored separately as the
-- key in the 'sshChannels' map.
data SshChannel = SshChannel
  { sshChannelState              :: SshChannelState

  , sshChannelId_them            :: Word32
  , sshChannelEnv                :: [(S.ByteString,S.ByteString)]
  , sshChannelWindowSize_them    :: Word32
  , sshChannelMaximumPacket_them :: Word32
  , sshChannelPty                :: (Maybe (S.ByteString, SshWindowSize, [(TerminalFlag, Word32)]))
  , sshChannelEvents             :: TChan SessionEvent

  -- | The original/max data window size.
  , sshChannelOrigWindowSize_us :: Word32
  -- | The number of bytes 'SessionEvent's in our 'sshChannelEvents'
  -- FIFO.
  , sshChannelFifoSize :: Word32
  -- | The number of bytes from them that our session handler has
  -- processed, but for which we have not sent them data window size
  -- updates.
  --
  -- From their point of view, our (remaining) window size is
  -- @sshChannelOrigWindowSize_us - sshChannelFifoSize -- sshChannelProcessedSize@.
  , sshChannelProcessedSize :: Word32
  }
