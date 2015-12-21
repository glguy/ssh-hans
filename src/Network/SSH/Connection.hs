{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DeriveFunctor #-}
{-# LANGUAGE CPP #-}
module Network.SSH.Connection where

import           Network.SSH.Messages
import           Network.SSH.Rekey
import           Network.SSH.State
import           Network.SSH.TerminalModes

import           Control.Concurrent
import           Control.Concurrent.STM
import           Control.Monad

import           Data.Word
import qualified Data.Map as Map
import           Data.Map ( Map )
import qualified Data.ByteString as S

import           Control.Monad.Trans.Class
import           Control.Monad.IO.Class
import           Control.Monad.Trans.Reader (ask, ReaderT(..), runReaderT)
import           Control.Monad.Trans.State (get,put,modify,StateT, evalStateT)

#if !MIN_VERSION_base(4,8,0)
import           Control.Applicative
#endif

data SshChannel = SshChannel
  { sshChannelId_them            :: !Word32
  , sshChannelEnv                :: [(S.ByteString,S.ByteString)]
  , sshChannelWindowSize_them    :: TVar Word32
  , sshChannelMaximumPacket_them :: Word32
  , sshChannelPty                :: Maybe (S.ByteString, SshWindowSize, [(TerminalFlag, Word32)])
  , sshChannelEvents             :: Chan SessionEvent

  -- | The original/max data window size.
  , sshChannelOrigWindowSize_us :: Word32
  -- | The number of bytes 'SessionEvent's in our 'sshChannelEvents'
  -- FIFO.
  , sshChannelFifoSize :: TVar Word32
  -- | The number of bytes from them that our session handler has
  -- processed, but for which we have not sent them data window size
  -- updates.
  --
  -- From their point of view, our (remaining) window size is
  -- @sshChannelOrigWindowSize_us - sshChannelFifoSize -- sshChannelProcessedSize@.
  , sshChannelProcessedSize :: TVar Word32
  }

----------------------
-- Connection operations
----------------------

newtype Connection a = Connection
  { unConnection :: ReaderT (Client, SshState) (StateT (Map Word32 SshChannel) IO) a }
  deriving (Functor, Applicative, Monad, MonadIO)

connectionReceive :: Connection SshMsg
connectionReceive = Connection $
  do (client, state) <- ask
     liftIO (receive client state)

connectionSend :: SshMsg -> Connection ()
connectionSend msg = Connection $
  do (client, state) <- ask
     liftIO (send client state msg)

connectionLog :: String -> Connection ()
connectionLog msg = Connection $
  do (client, _) <- ask
     liftIO (cLog client msg)

connectionGetChannels :: Connection (Map Word32 SshChannel)
connectionGetChannels = Connection (lift get)

connectionSetChannels :: Map Word32 SshChannel -> Connection ()
connectionSetChannels = Connection . lift . put

connectionModifyChannels :: (Map Word32 SshChannel -> Map Word32 SshChannel) -> Connection ()
connectionModifyChannels = Connection . lift . modify

----------------------

-- | Run a 'Connection' computation in 'IO'.
runConnection :: Client -> SshState -> Connection a -> IO a
runConnection client state
  = flip evalStateT Map.empty
  . flip runReaderT (client, state)
  . unConnection

-- | Send a channel-open request in a client.
sendChannelOpenSession :: Connection ()
sendChannelOpenSession =
  -- Some of the channel state corresponding to them is not defined yet,
  -- so we fill it in with 'error's until we know their values.
  do (client, state) <- Connection ask
     -- This initial window size and max packet size are what the
     -- OpenSSH client sends in my experiments.
     let origWindowSize_us  = 2097152
     let maximumPacket_us   = 32768
     let windowSize_them    = error "sendChannelOpen: bug: window_them!"
     let channelId_them     = error "sendChannelOpen: bug: channel_them!"
     let maximumPacket_them = error "sendChannelOpen: bug: max_packet_them!"
     (channelId_us, _) <- channelOpenHelper
       channelId_them windowSize_them maximumPacket_them origWindowSize_us
     liftIO $ send client state
       (SshMsgChannelOpen SshChannelTypeSession
         channelId_us origWindowSize_us maximumPacket_us)

-- | Listen for channel requests
--
-- Used by clients and servers, altho not all packets are allowed in
-- both clients and servers.
connectionService :: Connection ()
connectionService =
  do msg <- connectionReceive
     (client, state) <- Connection ask
     let role = sshRole state
     case msg of
       SshMsgKexInit i_them ->
         do liftIO (rekeyKeyExchange client state i_them)
            connectionService

       -- | RFC 4254 Section 6.1: clients should reject channel open.
       SshMsgChannelOpen _ senderChannel _ _ | role == ClientRole ->
         do rejectChannelOpenRequest senderChannel
            connectionService

       SshMsgChannelOpen SshChannelTypeSession
         senderChannel initialWindowSize maximumPacketSize ->
           do handleChannelOpenSession senderChannel
                initialWindowSize maximumPacketSize
              connectionService

       SshMsgChannelOpen (SshChannelTypeDirectTcpIp host port _h _p)
         senderChannel initialWindowSize maximumPacketSize ->
           do handleChannelOpenDirectTcp senderChannel initialWindowSize
                maximumPacketSize host port
              connectionService

       SshMsgChannelOpen _ senderChannel _ _ ->
         do rejectChannelOpenRequest senderChannel
            connectionService

       SshMsgChannelOpenConfirmation channelId_us channelId_them
         initialWindowSize_them maximumPacket_them
         | role == ServerRole -> fail "server does not open channels!"
         | otherwise ->
         do handleChannelOpenConfirmation channelId_us channelId_them
              initialWindowSize_them maximumPacket_them
            connectionService

       -- | RFC 4254 Section 6.5: client should ignore channel requests.
       SshMsgChannelRequest req chan wantReply
         | role == ClientRole -> connectionService
         | otherwise ->
         do handleChannelRequest req chan wantReply
            connectionService

       SshMsgChannelData chan bytes ->
         do handleChannelData chan bytes
            connectionService

       SshMsgChannelClose chan ->
         do handleChannelClose chan
            connectionService

       SshMsgChannelEof chan ->
         do handleChannelEof chan
            connectionService

       SshMsgChannelWindowAdjust chan adj ->
         do handleChannelWindowAdjust chan adj
            connectionService

       SshMsgDisconnect reason _desc _lang ->
            connectionLog ("Disconnect: " ++ show reason)
            -- TODO: tear down channels

       _ ->
         do connectionLog ("Unhandled message: " ++ show msg)
            connectionService

  where
    rejectChannelOpenRequest :: Word32 -> Connection ()
    rejectChannelOpenRequest senderChannel =
      connectionSend $
        SshMsgChannelOpenFailure senderChannel SshOpenAdministrativelyProhibited "" ""


-- | Handle a channel-open confirmation.
handleChannelOpenConfirmation :: Word32 -> Word32 -> Word32 -> Word32 -> Connection ()
handleChannelOpenConfirmation
  channelId_us channelId_them initialWindowSize_them maximumPacket_them =
  do channels <- connectionGetChannels
     channel <- maybe (fail "no such channel!") return $
       Map.lookup channelId_us channels
     liftIO $ atomically $ writeTVar (sshChannelWindowSize_them channel)
       initialWindowSize_them
     let channel' = channel
           { sshChannelId_them              = channelId_them
           , sshChannelMaximumPacket_them = maximumPacket_them
           }
     connectionSetChannels (Map.insert channelId_us channel' channels)

-- | Common code for opening a channel in a client or a server.
channelOpenHelper :: Word32 -> Word32 -> Word32 -> Word32 -> Connection (Word32, SshChannel)
channelOpenHelper channelId_them windowSize_them maximumPacket_them origWindowSize_us =
  do channels <- connectionGetChannels

     events <- liftIO newChan
     window <- liftIO $ newTVarIO windowSize_them

     fifoSize      <- liftIO $ newTVarIO 0
     processedSize <- liftIO $ newTVarIO 0

     let nextChannelId_us =
           case Map.maxViewWithKey channels of
             Nothing        -> 0
             Just ((k,_),_) -> k+1

         channel = SshChannel
                     { sshChannelId_them            = channelId_them
                     , sshChannelWindowSize_them    = window
                     , sshChannelMaximumPacket_them = maximumPacket_them
                     , sshChannelEnv                = []
                     , sshChannelPty                = Nothing
                     , sshChannelEvents             = events
                     , sshChannelOrigWindowSize_us  = origWindowSize_us
                     , sshChannelFifoSize           = fifoSize
                     , sshChannelProcessedSize      = processedSize
                     }

     connectionSetChannels (Map.insert nextChannelId_us channel channels)
     return (nextChannelId_us, channel)

-- | Handle a channel-open request of session type.
handleChannelOpenSession :: Word32 -> Word32 -> Word32 -> Connection ()
handleChannelOpenSession channelId_them initialWindowSize_them maximumPacket_them =
  do liftIO $ debug $
       "starting session: channel: " ++ show channelId_them ++
       ", window size: " ++ show initialWindowSize_them ++
       ", packet size: " ++ show maximumPacket_them
     (channelId_us, _) <- channelOpenHelper
       channelId_them initialWindowSize_them maximumPacket_them
       initialWindowSize_them
     -- In our response we offer them the same window size and max
     -- packet size that they offered we.
     connectionSend $
       SshMsgChannelOpenConfirmation
         channelId_them
         channelId_us
         initialWindowSize_them
         maximumPacket_them

-- | Handle a channel-open request of direct-tcp-ip type.
handleChannelOpenDirectTcp :: Word32 -> Word32 -> Word32 -> S.ByteString -> Word32 -> Connection ()
handleChannelOpenDirectTcp channelId_them initialWindowSize_them maximumPacket_them host port =
  do (channelId_us, channel) <- channelOpenHelper
       channelId_them initialWindowSize_them maximumPacket_them
       initialWindowSize_them

     (client,state) <- Connection ask
     success <- liftIO (cDirectTcp client host port (sshChannelEvents channel)
                          (channelWrite client state channel))

     connectionSend $
        if success
               -- In our response we offer them the same window size and max
               -- packet size that they offered we.
          then SshMsgChannelOpenConfirmation
                 channelId_them
                 channelId_us
                 initialWindowSize_them
                 maximumPacket_them
          else SshMsgChannelOpenFailure
                 channelId_them SshOpenAdministrativelyProhibited "" ""

-- | Handle a window adjust request from them.
handleChannelWindowAdjust :: Word32 -> Word32 -> Connection ()
handleChannelWindowAdjust channelId adj =
  do liftIO $ debug $
       "received window adjust: channel: " ++ show channelId ++
       ", adjust size: " ++ show adj
     channels <- connectionGetChannels
     case Map.lookup channelId channels of
       Nothing -> fail "Bad channel!"
       Just channel ->
         liftIO (atomically (modifyTVar' (sshChannelWindowSize_them channel) (+ adj)))

handleChannelEof :: Word32 -> Connection ()
handleChannelEof channelId =
  do channels <- connectionGetChannels
     case Map.lookup channelId channels of
       Nothing -> fail "Bad channel!"
       Just channel ->
            liftIO (writeChan (sshChannelEvents channel) SessionEof)

handleChannelClose :: Word32 -> Connection ()
handleChannelClose channelId =
  do channels <- connectionGetChannels
     case Map.lookup channelId channels of
       Nothing -> fail "Bad channel!"
       Just channel ->
         do liftIO (writeChan (sshChannelEvents channel) SessionClose)
            connectionSend (SshMsgChannelClose (sshChannelId_them channel))
            connectionSetChannels (Map.delete channelId channels)

-- | Handle channel data from them.
--
-- We need to periodically send them window adjust messages after
-- receiving channel data, or they'll stop sending! However, here we
-- put the received data into an unbounded FIFO (a
-- 'Control.Concurrent.Chan'), but don't actually process it yet. The
-- data in the channel is processed when the application backing the
-- channel on our end calls 'channelRead', so that is where window
-- adjustments are sent to them.
--
-- Here we check for data window overflows, and close the connection
-- if they overflow our window. This is stricter than the spec
-- mandates: RFC 4254 Section 5.2 says only that "Both parties MAY
-- ignore all extra data sent after the allowed window is empty."
handleChannelData :: Word32 -> S.ByteString -> Connection ()
handleChannelData channelId bytes =
  do channels <- connectionGetChannels
     case Map.lookup channelId channels of
       Nothing -> fail "Bad channel!"
       Just channel -> liftIO $ do
         overFlowed <- atomically $ do
           let origWindowSize = sshChannelOrigWindowSize_us channel
           let dataSize       = fromIntegral $ S.length bytes
           oldFifoSize   <- readTVar (sshChannelFifoSize channel)
           processedSize <- readTVar (sshChannelProcessedSize channel)

           -- Use 'Integer' to avoid overflow.
           if toInteger origWindowSize <
              toInteger oldFifoSize + toInteger processedSize +
                toInteger dataSize
           then return True
           else do
             -- There is a race condition between when the channel
             -- size is updated here in the transaction, and when the
             -- channel is actually updated below, outside the
             -- transaction. However, I can't think of any reason this
             -- race condition matters right now, since we only use
             -- the sizes to decide when to send a window adjust
             -- message, and we don't actually have any bounded
             -- buffers to overflow.
             writeTVar (sshChannelFifoSize channel) $!
               (oldFifoSize + dataSize)
             return False

         if overFlowed
         then fail $ "they overflowed our window!"
         else writeChan (sshChannelEvents channel) (SessionData bytes)

handleChannelRequest :: SshChannelRequest -> Word32 -> Bool -> Connection ()
handleChannelRequest request channelId wantReply =
  do channels <- connectionGetChannels

     case Map.lookup channelId channels of
       Nothing      -> connectionSend (SshMsgDisconnect SshDiscProtocolError "" "")
       Just channel ->
         do result <- handleRequest request channelId channel
            when wantReply $
              connectionSend $
                if result
                  then SshMsgChannelSuccess (sshChannelId_them channel)
                  else SshMsgChannelFailure (sshChannelId_them channel)

handleRequest :: SshChannelRequest -> Word32 -> SshChannel -> Connection Bool
handleRequest request channelId channel = do
  (client, state) <- Connection ask
  if sshRole state == ClientRole
  -- Most of the channel requests are supposed to be ignored by the
  -- client. Ignore them all for now.
  --
  -- A more flexible approach, which deviates from the standard, is to
  -- leave it up to the library user to decide whether these requests
  -- are supported in the client or not, by deciding whether to
  -- provide the corresponding callbacks or not.
  then return False
  else case request of
    SshChannelRequestPtyReq term winsize modes ->
      do let termios = case parseTerminalModes modes of
                         Left _   -> []
                         Right xs -> xs

             channel' = channel
               { sshChannelPty = Just (term, winsize, termios)
               }
         connectionModifyChannels (Map.insert channelId channel')
         return True

    SshChannelRequestEnv name value ->
      do let channel' = channel
               { sshChannelEnv = (name,value) : sshChannelEnv channel
               }
         connectionModifyChannels (Map.insert channelId channel')
         return True

    SshChannelRequestShell ->
      do case sshChannelPty channel of
           Nothing -> return False
           Just (term,winsize,termios) ->
             do _ <- liftIO $ forkIO $
                   cOpenShell client term winsize termios
                     (sshChannelEvents channel)
                     (channelWrite client state channel)
                return True

    SshChannelRequestExec command ->
      do liftIO $ cRequestExec client command
                   (channelRead client state channel)
                   (channelWrite client state channel)

    SshChannelRequestSubsystem subsystem ->
      do liftIO $ cRequestSubsystem client subsystem
                   (channelRead client state channel)
                   (channelWrite client state channel)

    SshChannelRequestWindowChange winsize ->
      do liftIO (writeChan (sshChannelEvents channel) (SessionWinsize winsize))
         return True -- TODO: inform the callback

-- | Write data to them, accounting for their window size.
channelWrite :: Client -> SshState -> SshChannel -> Maybe S.ByteString -> IO ()
channelWrite client state channel Nothing =
  send client state (SshMsgChannelClose (sshChannelId_them channel))

channelWrite client state channel (Just msg)
  | S.null msg = return ()
  | otherwise =
     do sendSize <- atomically $
          do window <- readTVar (sshChannelWindowSize_them channel)
             when (window == 0) retry
             let sendSize = minimum [ sshChannelMaximumPacket_them channel
                                    , window
                                    , fromIntegral (S.length msg)
                                    ]
             writeTVar (sshChannelWindowSize_them channel) $!
               (window - sendSize)
             return (fromIntegral sendSize)
        let (current,next) = S.splitAt sendSize msg
        send client state (SshMsgChannelData (sshChannelId_them channel) current)
        channelWrite client state channel (Just next)

-- | Read a session event from them, accounting for window size.
--
-- This function is intended for use by our session backends.
channelRead :: Client -> SshState -> SshChannel -> IO SessionEvent
channelRead client state channel = do
  event <- readChan (sshChannelEvents channel)
  case event of
    SessionData bs -> do
      windowAdjustSize <- atomically $ do
        let origWindowSize   = sshChannelOrigWindowSize_us channel
        let dataSize         = fromIntegral $ S.length bs
        oldProcessedSize    <- readTVar (sshChannelProcessedSize channel)
        let newProcessedSize = oldProcessedSize + dataSize

        oldFifoSize    <- readTVar (sshChannelFifoSize channel)
        let newFifoSize = oldFifoSize - dataSize
        writeTVar (sshChannelFifoSize channel) $! newFifoSize

        -- The 20 here is chosen to very naively approximate some of
        -- the observed behavior of the OpenSSH client. In tests it
        -- used an original window size of 2097152 bytes. When I sent
        -- small packets it adjusted the window after receiving about
        -- 99000 bytes, about one 20th of the window size. When I sent
        -- large packets it adjusted the window size by increments
        -- ranging from 32k to about 5000000 bytes. I don't know what
        -- algorithm OpenSSH actually uses internally to decide when
        -- to send window adjustments, but I'm assuming it's not very
        -- important.
        let bound              = origWindowSize `div` 20
        let timeToAdjustWindow = newProcessedSize >= bound
        if timeToAdjustWindow
        then do
          writeTVar (sshChannelProcessedSize channel) 0
          return newProcessedSize
        else do
          writeTVar (sshChannelProcessedSize channel) $! newProcessedSize
          return 0

      when (windowAdjustSize > 0) $ do
        debug $
          "sent window adjust: channel: " ++ show (sshChannelId_them channel) ++
          ", adjust size: " ++ show windowAdjustSize
        send client state
          (SshMsgChannelWindowAdjust
            (sshChannelId_them channel) windowAdjustSize)
      return event

    _ -> return event
