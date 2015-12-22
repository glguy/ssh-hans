{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DeriveFunctor #-}
{-# LANGUAGE CPP #-}
module Network.SSH.Connection where

import           Network.SSH.Messages
import           Network.SSH.Rekey
import           Network.SSH.State
import           Network.SSH.TerminalModes

import           Control.Concurrent.STM
import           Control.Monad

import           Data.Word
import qualified Data.Map as Map
import qualified Data.ByteString as S

import           Control.Monad.IO.Class
import           Control.Monad.Trans.Reader (ask, ReaderT(..), runReaderT)

#if !MIN_VERSION_base(4,8,0)
import           Control.Applicative
#endif

----------------------
-- Connection operations
----------------------

newtype Connection a = Connection
  { unConnection :: ReaderT (Client, SshState) IO a }
  deriving (Functor, Applicative, Monad, MonadIO)

-- | Run a 'Connection' computation in 'IO'.
runConnection :: Client -> SshState -> Connection a -> IO a
runConnection client state
  = flip runReaderT (client, state)
  . unConnection

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

----------------------------------------------------------------
-- Concurrency helpers for channel-state read and mutate.

-- | Get 'TVar' channel by (our side) id.
--
-- Disconnects if the requested channel does not exist. Assuming the
-- channel ID was provided by the client, the failure of the lookup
-- means the client is sending non-sense, so killing the connection
-- seems reasonable.
connectionGetChannelTVar :: ChannelId -> Connection (TVar SshChannel)
connectionGetChannelTVar c = do
  (_, state)  <- Connection ask
  -- We only want to "lock" the single, requested channel, so we read
  -- the channels in a separate transaction.
  channels    <- liftIO . atomically $ readTVar (sshChannels state)
  case Map.lookup c channels of
    Nothing -> do
      connectionSend (SshMsgDisconnect SshDiscProtocolError "" "")
      fail "connectionGetChannelTVar: bad channel!"
    Just channelTVar -> return channelTVar

-- | Look up a channel by (our side) id.
connectionGetChannel :: ChannelId -> Connection SshChannel
connectionGetChannel c = do
  channelTVar <- connectionGetChannelTVar c
  liftIO . atomically $ readTVar channelTVar

-- | Modify a channel.
--
-- This is atomic in the modified channel, but not in the channel map
-- itself.
connectionModifyChannel ::
  ChannelId -> (SshChannel -> SshChannel) -> Connection ()
connectionModifyChannel c f =
  connectionModifyChannelWithResult c $
    \channel -> return (f channel, ())

-- | Modify a channel, returning a result.
--
-- This is atomic in the modified channel, but not in the channel map
-- itself.
connectionModifyChannelWithResult ::
  ChannelId -> (SshChannel -> STM (SshChannel, a)) -> Connection a
connectionModifyChannelWithResult c f = do
  channelTVar <- connectionGetChannelTVar c
  liftIO . atomically $ do
    channel            <- readTVar channelTVar
    (channel', result) <- f channel
    writeTVar channelTVar channel'
    return result

----------------------------------------------------------------
-- Client-oriented channel operations.

-- | Send a channel-open request in a client.
sendChannelOpenSession :: Connection ChannelId
sendChannelOpenSession = do
  -- Some of the channel state corresponding to them is not defined
  -- yet, so we fill it in with 'error's until we know their values.
  --
  -- This initial window size and max packet size are what the OpenSSH
  -- client sends in my experiments.
  let origWindowSize_us  = 2097152
  let maximumPacket_us   = 32768
  let windowSize_them    = error "sendChannelOpen: bug: window_them!"
  let channelId_them     = error "sendChannelOpen: bug: channel_them!"
  let maximumPacket_them = error "sendChannelOpen: bug: max_packet_them!"
  channelId_us <- channelOpenHelper
    channelId_them windowSize_them maximumPacket_them origWindowSize_us
  connectionSend
    (SshMsgChannelOpen SshChannelTypeSession
      channelId_us origWindowSize_us maximumPacket_us)
  return channelId_us

----------------------------------------------------------------
-- Main loop for receiving channel messages in a client or server.

-- | Listen for channel requests
--
-- Used by clients and servers, altho not all packets are allowed in
-- both clients and servers.
--
-- This should be 'forkIO'd before initiating channel-based
-- communication.
connectionService :: Connection ()
connectionService =
  do msg <- connectionReceive
     (client, state) <- Connection ask
     let role = sshRole state
     case msg of
       SshMsgKexInit i_them ->
         do liftIO (rekeyKeyExchange client state i_them)
            connectionService

       -- RFC 4254 Section 5: either side my open a channel generally;
       -- RFC 4254 Section 6.1: clients should reject session-channel
       -- open requests.
       --
       -- For now we're rejecting all channel-open requests to the
       -- client, but we may want to relax this in the future.
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
handleChannelOpenConfirmation :: ChannelId -> ChannelId -> Word32 -> Word32 -> Connection ()
handleChannelOpenConfirmation
  channelId_us channelId_them initialWindowSize_them maximumPacket_them =
  connectionModifyChannel channelId_us $ \channel ->
   channel
     { sshChannelId_them            = channelId_them
     , sshChannelMaximumPacket_them = maximumPacket_them
     , sshChannelWindowSize_them    = initialWindowSize_them
     }

-- | Common code for opening a channel in a client or a server.
channelOpenHelper ::
  ChannelId -> Word32 -> Word32 -> Word32 -> Connection ChannelId
channelOpenHelper channelId_them windowSize_them maximumPacket_them origWindowSize_us =
  do (_, state) <- Connection ask
     liftIO . atomically $ do
       channels <- readTVar $ sshChannels state

       events <- newTChan
       let nextChannelId_us =
             case Map.maxViewWithKey channels of
               Nothing        -> 0
               Just ((k,_),_) -> k+1

           channel = SshChannel
                       { sshChannelId_them            = channelId_them
                       , sshChannelWindowSize_them    = windowSize_them
                       , sshChannelMaximumPacket_them = maximumPacket_them
                       , sshChannelEnv                = []
                       , sshChannelPty                = Nothing
                       , sshChannelEvents             = events
                       , sshChannelOrigWindowSize_us  = origWindowSize_us
                       , sshChannelFifoSize           = 0
                       , sshChannelProcessedSize      = 0
                       }

       channelTVar <- newTVar channel
       writeTVar (sshChannels state)
         (Map.insert nextChannelId_us channelTVar channels)
       return nextChannelId_us

-- | Handle a channel-open request of session type.
handleChannelOpenSession :: Word32 -> Word32 -> Word32 -> Connection ()
handleChannelOpenSession channelId_them initialWindowSize_them maximumPacket_them =
  do liftIO $ debug $
       "starting session: channel: " ++ show channelId_them ++
       ", window size: " ++ show initialWindowSize_them ++
       ", packet size: " ++ show maximumPacket_them
     channelId_us <- channelOpenHelper
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
handleChannelOpenDirectTcp :: ChannelId -> Word32 -> Word32 -> S.ByteString -> Word32 -> Connection ()
handleChannelOpenDirectTcp channelId_them initialWindowSize_them maximumPacket_them host port =
  do channelId_us <- channelOpenHelper
       channelId_them initialWindowSize_them maximumPacket_them
       initialWindowSize_them

     (client,state) <- Connection ask
     success <- liftIO (cDirectTcp client host port
                          (channelRead client state channelId_us)
                          (channelWrite client state channelId_us))

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
handleChannelWindowAdjust :: ChannelId -> Word32 -> Connection ()
handleChannelWindowAdjust channelId adj =
  do liftIO $ debug $
       "received window adjust: channel: " ++ show channelId ++
       ", adjust size: " ++ show adj
     connectionModifyChannel channelId $ \channel ->
       let !w = sshChannelWindowSize_them channel + adj in
       channel { sshChannelWindowSize_them = w }

-- | Handle EOF from them.
handleChannelEof :: ChannelId -> Connection ()
handleChannelEof channelId =
  -- This message does not affect window size accounting.
  do events <- sshChannelEvents <$> connectionGetChannel channelId
     liftIO . atomically $ (writeTChan events SessionEof)

-- | Handle channel close from them.
handleChannelClose :: ChannelId -> Connection ()
handleChannelClose channelId =
  -- This message does not affect window size accounting.
  do channel <- connectionGetChannel channelId
     liftIO . atomically $
       (writeTChan (sshChannelEvents channel) SessionClose)
     connectionSend (SshMsgChannelClose (sshChannelId_them channel))

     (_, state) <- Connection ask
     liftIO . atomically $ modifyTVar (sshChannels state)
       (Map.delete channelId)

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
handleChannelData :: ChannelId -> S.ByteString -> Connection ()
handleChannelData channelId bytes =
  do overFlowed <- connectionModifyChannelWithResult channelId $
       \channel -> do
       let origWindowSize = sshChannelOrigWindowSize_us channel
       let dataSize       = fromIntegral $ S.length bytes
       let oldFifoSize    = sshChannelFifoSize channel
       let processedSize  = sshChannelProcessedSize channel

       -- Use 'Integer' to avoid overflow.
       if toInteger origWindowSize <
          toInteger oldFifoSize + toInteger processedSize +
            toInteger dataSize
       then return (channel, True)
       else do
         writeTChan (sshChannelEvents channel) (SessionData bytes)
         let !newFifoSize = oldFifoSize + dataSize
         let channel' = channel { sshChannelFifoSize = newFifoSize }
         return (channel', False)

     when overFlowed $
       fail $ "they overflowed our window!"

handleChannelRequest ::
  SshChannelRequest -> ChannelId -> Bool -> Connection ()
handleChannelRequest request channelId wantReply = do
  (client, state) <- Connection ask
  id_them <- sshChannelId_them <$> connectionGetChannel channelId
  if sshRole state == ClientRole
  -- Most of the channel requests are supposed to be ignored by the
  -- client. Ignore them all for now.
  --
  -- A more flexible approach, which deviates from the standard, is to
  -- leave it up to the library user to decide whether these requests
  then connectionSend $ SshMsgChannelFailure id_them
  else do
    successIO <- connectionModifyChannelWithResult channelId
                   (go client state)
    success   <- liftIO successIO
    when wantReply $ connectionSend $
      if success
      then SshMsgChannelSuccess id_them
      else SshMsgChannelFailure id_them

  where
  -- | Handle a request while possibly modifying the channel.
  --
  -- Returns a computation which determines if the request was
  -- successful.
  go :: Client -> SshState -> SshChannel -> STM (SshChannel, IO Bool)
  go client state channel = case request of
    SshChannelRequestPtyReq term winsize modes ->
      do let termios = case parseTerminalModes modes of
                         Left _   -> []
                         Right xs -> xs

             channel' = channel
               { sshChannelPty = Just (term, winsize, termios)
               }
         return (channel', return True)

    SshChannelRequestEnv name value ->
      do let channel' = channel
               { sshChannelEnv = (name,value) : sshChannelEnv channel
               }
         return (channel', return True)

    SshChannelRequestShell ->
      do case sshChannelPty channel of
           Nothing -> return (channel, return False)
           Just (term,winsize,termios) -> do
             let continuation =
                   cOpenShell client term winsize termios
                     (channelRead client state channelId)
                     (channelWrite client state channelId)
             return (channel, continuation)

    SshChannelRequestExec command ->
      do let continuation =
               cRequestExec client command
                 (channelRead client state channelId)
                 (channelWrite client state channelId)
         return (channel, continuation)

    SshChannelRequestSubsystem subsystem ->
      do let continuation =
               cRequestSubsystem client subsystem
                 (channelRead client state channelId)
                 (channelWrite client state channelId)
         return (channel, continuation)

    SshChannelRequestWindowChange winsize ->
      do let continuation = liftIO . atomically $ do
               -- Sending the winsize event does not affect data
               -- windows, so we don't need to do accounting here as
               -- in 'handleChannelData'.
               writeTChan (sshChannelEvents channel)
                 (SessionWinsize winsize)
               return True
         return (channel, continuation)

----------------------------------------------------------------
-- Operations for communicating with them over channel.

-- | Write data to them, accounting for their window size.
--
-- Sending 'Nothing' closes the connection.
--
-- This function is intended for use by our session backends.
--
-- It might be better to expose the 'SessionEvent' API here, which
-- would allow a backend to additionally send 'SessionWinsize' and
-- 'SessionEof' events to them.
channelWrite :: Client -> SshState -> ChannelId -> Maybe S.ByteString -> IO ()
channelWrite client state channelId Nothing = runConnection client state $ do
  channel <- connectionGetChannel channelId
  connectionSend (SshMsgChannelClose (sshChannelId_them channel))

channelWrite client state channelId (Just msg') = runConnection client state $ do
  id_them <- sshChannelId_them <$> connectionGetChannel channelId
  go id_them msg'
  where
  go id_them msg
    | S.null msg = return ()
    | otherwise =
     do sendSize <- connectionModifyChannelWithResult channelId $ \channel ->
          do let window = sshChannelWindowSize_them channel
             when (window == 0) retry
             let sendSize = minimum [ sshChannelMaximumPacket_them channel
                                    , window
                                    , fromIntegral (S.length msg)
                                    ]
             let !window' = window - sendSize
             let channel' = channel
                   { sshChannelWindowSize_them = window' }
             return (channel', fromIntegral sendSize)

        let (current,next) = S.splitAt sendSize msg
        connectionSend (SshMsgChannelData id_them current)
        go id_them next

-- | Read a session event from them, accounting for window size.
--
-- This function is intended for use by our session backends.
channelRead :: Client -> SshState -> ChannelId -> IO SessionEvent
channelRead client state channelId = runConnection client state $ do
  (windowAdjustSize, event) <-
    connectionModifyChannelWithResult channelId $ \channel -> do
    event <- readTChan (sshChannelEvents channel)
    case event of
      SessionData bs -> do
        let origWindowSize    = sshChannelOrigWindowSize_us channel
        let dataSize          = fromIntegral $ S.length bs
        let oldProcessedSize  = sshChannelProcessedSize channel
        let !newProcessedSize = oldProcessedSize + dataSize

        let oldFifoSize  = sshChannelFifoSize channel
        let !newFifoSize = oldFifoSize - dataSize

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
          let channel' = channel
                { sshChannelFifoSize      = newFifoSize
                , sshChannelProcessedSize = 0
                }
          return (channel', (newProcessedSize, event))
        else do
          let channel' = channel
                { sshChannelFifoSize      = newFifoSize
                , sshChannelProcessedSize = newProcessedSize
                }
          return (channel', (0, event))
      _ -> return (channel, (0, event))

  when (windowAdjustSize > 0) $ do
    id_them <- sshChannelId_them <$> connectionGetChannel channelId
    liftIO $ debug $
      "sent window adjust: channel: " ++ show id_them ++
      ", adjust size: " ++ show windowAdjustSize
    connectionSend (SshMsgChannelWindowAdjust id_them windowAdjustSize)
  return event
