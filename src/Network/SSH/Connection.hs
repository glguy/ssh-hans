-- |
-- Description: SSH channels
--
-- An implementation of SSH channels as described in
-- /RFC 4254 SSH Connection Protocol/.
--
-- Throughout this module we use "session backend" to refer to a
-- handler for "exec", "shell", or "subsystem" requests on a session
-- channel.
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

import qualified Data.ByteString as S
import qualified Data.ByteString.Char8 as C8
import qualified Data.Map as Map
import           Data.Word

import           Control.Monad.IO.Class
import           Control.Monad.Trans.Reader (ask, ReaderT(..), runReaderT)

#if !MIN_VERSION_base(4,8,0)
import           Control.Applicative
#endif

----------------------
-- * Connection operations
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
-- * Concurrency helpers for channel-state read and mutate.

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
      fail $ "connectionGetChannelTVar: no such channel: " ++ show c ++ "!"
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
-- * Client-oriented channel operations.

-- | Send a channel-open request in a client.
--
-- TODO(conathan): if we instead returned a 'TVar SshChannel' here,
-- and maybe embedded our channel id in the 'SshChannel', we'd be free
-- to delete a channel from the channel map without worrying a client
-- later looking it up by id and failing. In any case, we need a
-- better story around closing and cleaning up channels.
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
  channelId_us <- channelOpenHelper SshChannelStateOpenRequested
    channelId_them windowSize_them maximumPacket_them origWindowSize_us
  connectionSend
    (SshMsgChannelOpen SshChannelTypeSession
      channelId_us origWindowSize_us maximumPacket_us)

  -- Wait for them to confirm or reject the channel open before
  -- continuing.
  channelTVar  <- connectionGetChannelTVar channelId_us
  channelState <- liftIO . atomically $ do
    channelState <- sshChannelState <$> readTVar channelTVar
    when (channelState == SshChannelStateOpenRequested) retry
    return channelState
  case channelState of
    SshChannelStateOpen -> do
      liftIO . debug $ "opened session: channel: " ++ show channelId_us
      return channelId_us
    SshChannelStateOpenFailed reason desc _lang ->
      fail $ "channel-open request rejected: reason code: " ++
             show reason ++ ", reason string: " ++ C8.unpack desc
    _ -> fail $ "unexpected channel state: " ++ show channelState

-- | Send them a subsystem request on an existing session channel.
--
-- Returns read and write functions for interacting with them via the
-- channel. Sending 'Nothing' to the write function closes the
-- channel.
sendChannelRequestSubsystem ::
  ChannelId  -> S.ByteString ->
  Connection (IO SessionEvent, Maybe S.ByteString -> IO ())
sendChannelRequestSubsystem id_us subsystem = do
  liftIO . debug $ "requesting subsystem: channel: " ++ show id_us ++
                   ", subsystem: " ++ C8.unpack subsystem
  channel <- connectionGetChannel id_us
  when (sshChannelState channel /= SshChannelStateOpen) $
    fail "channel state incompatible with subsystem request!"

  -- Set state to "subsystem requested" *before* actually sending the
  -- request, since otherwise there would be a race condition between
  -- setting the channel state and receiving the subsystem request
  -- confirmation from them.
  connectionModifyChannel id_us $ \channel' ->
    channel' { sshChannelState = SshChannelStateBackendRequested }
  connectionSend $
    SshMsgChannelRequest (SshChannelRequestSubsystem subsystem)
      (sshChannelId_them channel) True

  -- Wait for them to confirm or reject the request.
  channelTVar  <- connectionGetChannelTVar id_us
  channelState <- liftIO . atomically $ do
    channelState <- sshChannelState <$> readTVar channelTVar
    when (channelState == SshChannelStateBackendRequested) retry
    return channelState
  when (channelState /= SshChannelStateBackendRunning) $
    fail "subsystem request failed!"
  (client, state) <- Connection ask
  return ( channelRead client state id_us
         , channelWrite client state id_us
         )

----------------------------------------------------------------
-- * Main loop for receiving channel messages in a client or server.

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
         initialWindowSize_them maximumPacket_them ->
         do handleChannelOpenConfirmation channelId_us channelId_them
              initialWindowSize_them maximumPacket_them
            connectionService

       SshMsgChannelOpenFailure id_us reason desc lang ->
         do handleChannelOpenFailure id_us reason desc lang
            connectionService

       -- RFC 4254 Section 6.2, 6.5: client should ignore *some*
       -- channel requests.
       --
       -- We're actually ignoring *all* channel requests, so we may
       -- want to relax this later.
       SshMsgChannelRequest req chan wantReply
         | role == ClientRole ->
         do liftIO . debug $
              "ignoring channel request received in client: channel" ++ show chan ++
              ", request type: " ++ show (sshChannelRequestTag req) ++
              ", want reply: " ++ show wantReply
            connectionService
         | otherwise ->
         do handleChannelRequest req chan wantReply
            connectionService

       SshMsgChannelSuccess chan ->
         do handleChannelSuccessOrFailure True chan
            connectionService
       SshMsgChannelFailure chan ->
         do handleChannelSuccessOrFailure False chan
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
  channelId_us channelId_them initialWindowSize_them maximumPacket_them = do
  success <- connectionModifyChannelWithResult channelId_us $ \channel ->
   if sshChannelState channel == SshChannelStateOpenRequested
   then do
     let channel' = channel
           { sshChannelState              = SshChannelStateOpen
           , sshChannelId_them            = channelId_them
           , sshChannelMaximumPacket_them = maximumPacket_them
           , sshChannelWindowSize_them    = initialWindowSize_them
           }
     return (channel', True)
   else
     return (channel, False)

  when (not success) $
    fail $ "unexpected channel-open confirmation: channel: " ++ show channelId_us

-- | Handle a channel-open failure.
--
-- It's up to the channel opener to display the rejection reason.
handleChannelOpenFailure ::
  ChannelId -> SshOpenFailure -> S.ByteString -> S.ByteString -> Connection ()
handleChannelOpenFailure id_us reason description language = do
  connectionModifyChannel id_us $ \channel ->
    channel { sshChannelState = SshChannelStateOpenFailed reason description language }

-- | Handle request success ('True') or failure ('False').
--
-- Our treatment depends on the state of the channel:
--
-- - if a session backend is already running, then we assume the
--   request was generated by the backend and we pass the response to
--   the backend.
--
-- - if a session backend has been requested, then we update the state
--   back to "open", to indicate failure. We might instead want a
--   separate "backend request failed" state to avoid any possible
--   ambiguity.
handleChannelSuccessOrFailure :: Bool -> ChannelId -> Connection ()
handleChannelSuccessOrFailure success id_us = do
  channel <- connectionGetChannel id_us
  let channelState = sshChannelState channel
  liftIO . debug $
    "channel-request response: channel " ++ show id_us ++
    ", response: " ++ (if success then "success" else "failure") ++
    ", state: " ++ show channelState

  case channelState of
    SshChannelStateBackendRunning -> do
      let events = sshChannelEvents channel
      liftIO . atomically $
        writeTChan events (SessionRequestResponse success)
    SshChannelStateBackendRequested ->
      connectionModifyChannel id_us $ \channel' ->
        channel' { sshChannelState = if success
                                     then SshChannelStateBackendRunning
                                     else SshChannelStateOpen
                 }
    -- TODO(conathan): This is wrong for clients sending e.g. "env"
    -- requests or "pty" requests before requesting a session
    -- backend. In those cases we would be in "open" state. We could
    -- track both requests and responses, in order to match them up
    -- more easily: the responses are required to come in order, altho
    -- non-request/response messages may be interspersed.
    _ -> fail $ "received channel-request in unexpected channel state: " ++
                show channelState

-- | Common code for opening a channel in a client or a server.
channelOpenHelper ::
  SshChannelState -> ChannelId -> Word32 -> Word32 -> Word32 ->
  Connection ChannelId
channelOpenHelper initialState' channelId_them windowSize_them maximumPacket_them origWindowSize_us =
  do (_, state) <- Connection ask
     liftIO . atomically $ do
       channels <- readTVar $ sshChannels state

       events <- newTChan
       let nextChannelId_us =
             case Map.maxViewWithKey channels of
               Nothing        -> 0
               Just ((k,_),_) -> k+1

           channel = SshChannel
                       { sshChannelState              = initialState'
                       , sshChannelId_them            = channelId_them
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
     channelId_us <- channelOpenHelper SshChannelStateOpen
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
  do channelId_us <- channelOpenHelper SshChannelStateOpen
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

-- | Handle a channel-request msg.
--
-- The allowable channel requests and their implications are
-- complicated. For example:
--
-- - an X11 forwarding request (not implemented below) must be sent on
--   a session channel before and X11 channel can be opened separately
--   (RFC 4254 Section 6.3).
--
-- - only one "shell", "exec", or "subsystem" session-backend request
--   can be sent on a session channel during its lifetime.
--
-- - sending "env" requests after a session backend has been started
--   probably doesn't make sense (RFC 4254 Section 6.4: "Environment
--   variables may be passed to the shell/command to be started
--   *later*.")
--
-- TODO(conathan): this code is a mess and should be untangled. The
-- basic problem is that not all channel requests are in the same
-- logical class, even though RFC 4254 and hence our data types group
-- them together. Tracking more state in individual channels would get
-- us pretty far here: knowing if a backend has been started yet, and
-- if an X11 forwarded request has been received are enough to handle
-- the above examples.
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
      -- Only allow PTY allocation before a session backend is
      -- started. The RFC 4254 doesn't actually say to enforce this,
      -- but I'm not sure what it would mean to allocate the PTY after
      -- starting the backend.
      if sshChannelState channel /= SshChannelStateOpen
      then return (channel, return False)
      else do
        let termios = case parseTerminalModes modes of
                         Left _   -> []
                         Right xs -> xs

            channel' = channel
              { sshChannelPty = Just (term, winsize, termios) }
        return (channel', return True)

    SshChannelRequestEnv name value ->
      -- Only allow env changes before a session backend is
      -- started. The RFC 4254 doesn't actually say to enforce this --
      -- but see the first sentence of Section 6.4 -- but if we do
      -- allow setting env vars when a backend is running then we need
      -- to notify the backend.
      --
      -- The obvious way to notify the backend is to add a new kind of
      -- 'SessionEvent' for env-var requests.
      if sshChannelState channel /= SshChannelStateOpen
      then do
        let k = do
              debug "rejecting an env var update; this may be a bug!"
              return False
        return (channel, k)
      else do
        let channel' = channel
              { sshChannelEnv = (name,value) : sshChannelEnv channel
              }
        return (channel', return True)

    SshChannelRequestShell ->
      do case sshChannelPty channel of
           -- This is probably not correct, technically: you can start
           -- a shell without a PTY in OpenSSH with 'ssh -T <host>'.
           Nothing -> return (channel, return False)
           Just (term,winsize,termios) -> do
             let continuation =
                   cOpenShell client term winsize termios
                     (channelRead client state channelId)
                     (channelWrite client state channelId)
             guardBackendRequest continuation

    -- TODO(conathan): this request ("exec") and the "subsystem"
    -- request should also find out whether a PTY has been allocated.
    SshChannelRequestExec command ->
      do let continuation =
               cRequestExec client command
                 (channelRead client state channelId)
                 (channelWrite client state channelId)
         guardBackendRequest continuation

    SshChannelRequestSubsystem subsystem ->
      do let continuation =
               cRequestSubsystem client subsystem
                 (channelRead client state channelId)
                 (channelWrite client state channelId)
         guardBackendRequest continuation

    SshChannelRequestWindowChange winsize ->
      do let continuation = liftIO . atomically $ do
               -- Sending the winsize event does not affect data
               -- windows, so we don't need to do accounting here as
               -- in 'handleChannelData'.
               writeTChan (sshChannelEvents channel)
                 (SessionWinsize winsize)
               return True
         return (channel, continuation)

    where
    -- Check and update state for backend request.
    --
    -- A session backend can only be started once on a channel (and
    -- only for session channels, altho we don't check that).
    guardBackendRequest ::
      IO Bool -> STM (SshChannel, IO Bool)
    guardBackendRequest k = do
      if sshChannelState channel /= SshChannelStateOpen
      then return (channel, fail "bad backend request!")
      else do
        let k' = do
              success <- k
              when success $
                runConnection client state $
                  connectionModifyChannel channelId $ \channel' ->
                    channel'
                      { sshChannelState = SshChannelStateBackendRunning }
              return success
        return (channel, k')

----------------------------------------------------------------
-- * Operations for communicating with them over channel.
--
-- These operations are intended for use by session backends, altho it
-- would make sense to generalize them for internal use in this module
-- as well.

-- | Write data to them, accounting for their window size.
--
-- Sending 'Nothing' closes the connection.
--
-- It might be better to expose the 'SessionEvent' API here, which
-- would allow a backend to additionally send 'SessionWinsize' and
-- 'SessionEof' events to them.
channelWrite :: Client -> SshState -> ChannelId -> Maybe S.ByteString -> IO ()
channelWrite client state channelId Nothing = runConnection client state $ do
  channel <- connectionGetChannel channelId
  connectionSend (SshMsgChannelClose (sshChannelId_them channel))
  -- TODO(conathan): actually clean up the channel. We also need to
  -- handle (somewhere else) the case where we receive a "channel
  -- close" over the network: notify the backend and let it send a
  -- channel close back? Or, just send the close ourselves, and simply
  -- notify the backend that it happened.
  --
  -- See also comment above 'sendChannelOpenSession' re safely
  -- removing channels from the channel map.

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
