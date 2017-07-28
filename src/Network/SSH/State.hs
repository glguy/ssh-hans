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
import           Control.Exception ( Exception, throwIO )
import           Control.Monad
import           Crypto.Random
import qualified Data.ByteString as S
import qualified Data.ByteString.Char8 as S8
import qualified Data.ByteString.Lazy as L
import           Data.ByteString.Short (ShortByteString)
import           Data.Char ( isControl, showLitChar )
import           Data.IORef
import           Data.Map.Strict ( Map )
import qualified Data.Map.Strict as Map
import           Data.Serialize
import           Data.Word
import qualified System.IO as IO

----------------------------------------------------------------
-- Logging.

-- | Optional debugging using 'cLog' to sanitize control chars.
debug :: SshState -> String -> IO ()
debug = debugWithLevel . sshDebugLevel

-- | A version of 'debug' that can be called when no 'SshState' is
-- available.
debugWithLevel :: Int -> String -> IO ()
debugWithLevel debugLevel msg = do
  when (debugLevel > 0) $ do
    tid <- myThreadId
    safeLog $ "ssh-hans: " ++ show tid ++ ": " ++ msg

-- | Safe console logger.
safeLog :: String -> IO ()
safeLog = putStrLn . sanitizeControlChars

-- | Replace control chars to avoid terminal attacks.
--
-- The SSH RFCs suggest that terminal output be sanitized.
sanitizeControlChars :: String -> String
sanitizeControlChars = concatMap replace
  where
  replace c | isControl c = showLitChar c ""
            | otherwise = [c]

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
  deriving (Eq, Show)

type CAuthHandler =
     SshSessionId ->
     S.ByteString ->
     SshService ->
     SshAuthMethod ->
     IO AuthResult

type CRequestSubsystem =
     S.ByteString ->
     IO SessionEvent ->
     (Maybe S.ByteString -> IO ()) ->
     IO Bool

-- | Connection state.
--
-- We need something we can instantiate for the 'Handle' type provided
-- by the @network@ package, and for the @TcpSocket@ type provided by
-- @HaNS@.
data HandleLike = HandleLike
  { cGet   :: Int -> IO S.ByteString
  -- ^ Read up to 'n' bytes from network socket
  , cPut   :: L.ByteString -> IO ()
  -- ^ Put bytes on network socket
  , cClose :: IO ()
  -- ^ Close network socket
  }

handle2HandleLike :: IO.Handle -> HandleLike
handle2HandleLike h = HandleLike
  { cGet   = S.hGetSome h
  , cPut   = S.hPutStr  h . L.toStrict
  , cClose = IO.hClose  h
  }

-- | Session handlers for a server.
--
-- The session backends here -- 'cOpenShell', 'cDirectTcp',
-- 'cRequestSubsystem', 'cRequestExec' -- are expected to return
-- immediately with a boolean indicating whether the requested
-- operation was allowed or not. So, implementers probably want to use
-- 'forkIO' or similar to run session backends in a separate thread.
data SessionHandlers = SessionHandlers
  { cOpenShell   :: S.ByteString ->
                    SshWindowSize ->
                    [(TerminalFlag, Word32)] ->
                    IO SessionEvent ->
                    (Maybe S.ByteString -> IO ()) ->
                    IO Bool
  -- ^ TERM, initial window dimensions, termios flags, incoming
  -- events, write callback

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
  , cRequestSubsystem :: CRequestSubsystem

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
  , cAuthHandler :: CAuthHandler
  }

-- | Default, reject-all session handlers.
defaultSessionHandlers :: SessionHandlers
defaultSessionHandlers = SessionHandlers
  -- Make all requests fail immediately.
  --
  -- The empty list in 'AuthFailed []' means there are no auth methods
  -- by which the client can continue authentication. The OpenSSH
  -- client quits when receiving this.
  { cAuthHandler      = \_ _ _ _   -> return $ AuthFailed [] False
  -- These non-auth requests are only allowed after auth succeeds, and
  -- so will never be called for the default 'cAuthHandler' above.
  , cOpenShell        = \_ _ _ _ _ -> return False
  , cDirectTcp        = \_ _ _ _   -> return False
  , cRequestSubsystem = \_ _ _     -> return False
  , cRequestExec      = \_ _ _     -> return False
  }

----------------------------------------------------------------
-- Roles

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

----------------------------------------------------------------
-- Network IO

send :: HandleLike -> SshState -> SshMsg -> IO ()
send h SshState { .. } msg =
  modifyMVar_ sshSendState $ \(seqNum, cipher, activeCipher, mac, comp, gen) ->
    do payload <- comp (runPut (putSshMsg msg))
       let (pkt,activeCipher',gen') = putSshPacket seqNum cipher activeCipher mac gen payload
       -- TODO(conathan): how to tell if the connection is closed
       -- here? Would like to raise an error when trying to write to a
       -- closed connection, no?
       cPut h pkt
       return (seqNum+1, cipher, activeCipher',mac, comp, gen')

-- | Like 'receive', but fail when receiving an unexpected msg.
receiveSpecific :: SshMsgTag -> HandleLike -> SshState -> IO SshMsg
receiveSpecific tag h sshState = do
  msg <- receive h sshState
  if sshMsgTag msg == tag
  then return msg
  else fail $ "unexpected msg of type" ++ show (sshMsgTag msg)

-- | Receive a message over the network.
--
-- Raises a 'SsshMsgDisconnectException' exception when receiving
-- 'SshMsgDisconnect'. Somewhere up the call stack someone should
-- catch this exception and do any clean up necessary: servers should
-- clean up all client state for the connection, and clients should
-- shut down.
receive :: HandleLike -> SshState -> IO SshMsg
receive h SshState { .. } = loop
  where
  loop =
    do (seqNum, cipher, activeCipher, mac, decomp) <- readIORef sshRecvState
       (payload, activeCipher') <- parseFrom h sshBuf
                                 $ getSshPacket seqNum cipher activeCipher mac
       payload' <- decomp payload
       msg <- either fail return $ runGetLazy getSshMsg payload'
       let !seqNum1 = seqNum + 1
       writeIORef sshRecvState (seqNum1, cipher, activeCipher', mac, decomp)
       case msg of
         SshMsgIgnore _                      -> loop
         SshMsgDebug display m _ | display   -> do safeLog (S8.unpack m)
                                                   loop -- XXX drop controls
                                 | otherwise -> loop
         SshMsgDisconnect reason msg' lang   ->
           throwIO $ SshMsgDisconnectException reason msg' lang
         _                                   -> return msg

-- | Exception raised when 'SshMsgDisconnect' is received.
data SshMsgDisconnectException
  = SshMsgDisconnectException
    { smdeReason :: SshDiscReason
    , smdeMsg    :: S.ByteString
    , smdeLang   :: S.ByteString
    }
  deriving Show
instance Exception SshMsgDisconnectException

parseFrom :: HandleLike -> IORef S.ByteString -> Get a -> IO a
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
-- need to be refined to handle other channel types. For example,
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
  | SshChannelStateCloseSent        -- ^ A channel close has been sent.
  | SshChannelStateCloseReceived    -- ^ A channel close has been received.
  | SshChannelStateClosed           -- ^ A channel close has been sent and received.
  deriving (Eq, Show)

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
    -- | Events we received from them over the network, that are yet
    -- to be consumed by the session handler underlying the channel.
  , sshChannelEventsReceived     :: TChan SessionEvent
    -- | Events produced by our session handler that we need to send
    -- to them over the network.
  , sshChannelEventsToSend       :: TChan SessionEvent
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
