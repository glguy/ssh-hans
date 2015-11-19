{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DeriveFunctor #-}
module Network.SSH.Connection where

import Network.SSH.Messages
import Network.SSH.State
import Network.SSH.TerminalModes

import Control.Concurrent
import Control.Concurrent.STM
import Control.Monad
import Control.Applicative

import Data.Maybe (fromJust)
import Data.Word
import qualified Data.Map as Map
import           Data.Map ( Map )
import qualified Data.ByteString as S

import Control.Monad.Trans.Class
import Control.Monad.IO.Class
import Control.Monad.Trans.Reader (ask, ReaderT(..), runReaderT)
import Control.Monad.Trans.State (get,put,modify,StateT, evalStateT)

data SshChannel = SshChannel
  { sshChannelRemote        :: !Word32
  , sshChannelEnv           :: [(S.ByteString,S.ByteString)]
  , sshChannelWindowSize    :: TVar Word32
  , sshChannelMaximumPacket :: Word32
  , sshChannelPty           :: Maybe (S.ByteString, SshWindowSize, [(TerminalFlag, Word32)])
  , sshChannelEvents        :: Chan SessionEvent
  }

----------------------
-- Connection operations
----------------------

newtype Connection a = Connection
  { runConnection :: ReaderT (Client, SshState) (StateT (Map Word32 SshChannel) IO) a }
  deriving (Functor, Applicative, Monad, MonadIO)

connectionReceive :: Connection SshMsg
connectionReceive = Connection $
  do (client, state) <- ask
     liftIO (receive client state)

connectionSend :: SshMsg -> Connection ()
connectionSend msg = Connection $
  do (client, state) <- ask
     liftIO (send client state msg)

connectionGetChannels :: Connection (Map Word32 SshChannel)
connectionGetChannels = Connection (lift get)

connectionSetChannels :: Map Word32 SshChannel -> Connection ()
connectionSetChannels = Connection . lift . put

connectionModifyChannels :: (Map Word32 SshChannel -> Map Word32 SshChannel) -> Connection ()
connectionModifyChannels = Connection . lift . modify

----------------------

startConnectionService :: Client -> SshState -> IO ()
startConnectionService client state
  = flip evalStateT Map.empty
  . flip runReaderT (client, state)
  . runConnection
  $ connectionService

connectionService :: Connection ()
connectionService =
  do msg <- connectionReceive
     liftIO (print msg)
     case msg of
       SshMsgChannelOpen SshChannelTypeSession
         senderChannel initialWindowSize maximumPacketSize ->
           do startSession senderChannel initialWindowSize maximumPacketSize
              connectionService

       SshMsgChannelOpen _ senderChannel _ _ ->
           do connectionSend $
                SshMsgChannelOpenFailure senderChannel SshOpenAdministrativelyProhibited "" ""
              connectionService

       SshMsgChannelRequest req chan wantReply ->
         do channelRequest req chan wantReply
            connectionService

       SshMsgChannelData chan bytes ->
         do channelData chan bytes
            connectionService

       SshMsgChannelClose chan ->
         do channelClose chan
            connectionService

       SshMsgChannelWindowAdjust chan adj ->
         do windowAdjust chan adj
            connectionService

       SshMsgDisconnect reason _desc _lang ->
            liftIO (putStrLn ("Disconnect: " ++ show reason))
            -- TODO: tear down channels

       _ -> return ()


startSession :: Word32 -> Word32 -> Word32 -> Connection ()
startSession senderChannel initialWindowSize maximumPacketSize =
  do channels <- connectionGetChannels

     events <- liftIO newChan
     window <- liftIO (atomically (newTVar initialWindowSize))

     let nextChannelId =
           case Map.maxViewWithKey channels of
             Nothing        -> 0
             Just ((k,_),_) -> k+1

         channel = SshChannel
                     { sshChannelRemote        = senderChannel
                     , sshChannelWindowSize    = window
                     , sshChannelMaximumPacket = maximumPacketSize
                     , sshChannelEnv           = []
                     , sshChannelPty           = Nothing
                     , sshChannelEvents        = events
                     }

     connectionSetChannels (Map.insert nextChannelId channel channels)

     connectionSend $
       SshMsgChannelOpenConfirmation
         senderChannel
         nextChannelId
         initialWindowSize
         maximumPacketSize

windowAdjust :: Word32 -> Word32 -> Connection ()
windowAdjust channelId adj =
  do channels <- connectionGetChannels
     case Map.lookup channelId channels of
       Nothing -> fail "Bad channel!"
       Just channel ->
         liftIO (atomically (modifyTVar' (sshChannelWindowSize channel) (+ adj)))

channelClose :: Word32 -> Connection ()
channelClose channelId =
  do channels <- connectionGetChannels
     case Map.lookup channelId channels of
       Nothing -> fail "Bad channel!"
       Just channel ->
         do liftIO (writeChan (sshChannelEvents channel) SessionClose)
            connectionSend (SshMsgChannelClose (sshChannelRemote channel))
            connectionSetChannels (Map.delete channelId channels)

channelData :: Word32 -> S.ByteString -> Connection ()
channelData channelId bytes =
  do channels <- connectionGetChannels
     case Map.lookup channelId channels of
       Nothing -> fail "Bad channel!"
       Just channel -> liftIO
                     $ writeChan (sshChannelEvents channel)
                     $ SessionData bytes

channelRequest :: SshChannelRequest -> Word32 -> Bool -> Connection ()
channelRequest request channelId wantReply =
  do channels <- connectionGetChannels

     case Map.lookup channelId channels of
       Nothing      -> connectionSend (SshMsgDisconnect SshDiscProtocolError "" "")
       Just channel ->
         do result <- handleRequest request channelId channel
            when wantReply $
              connectionSend $
                if result
                  then SshMsgChannelSuccess (sshChannelRemote channel)
                  else SshMsgChannelFailure (sshChannelRemote channel)

handleRequest :: SshChannelRequest -> Word32 -> SshChannel -> Connection Bool
handleRequest request channelId channel =
  case request of
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
      do (client, state) <- Connection ask
         liftIO $
           do _ <- forkIO $
                      cOpenShell client (fromJust (sshChannelPty channel))
                        (sshChannelEvents channel)
                        (channelWrite client state channelId channel)
              return True
    SshChannelRequestExec _command        -> return False
    SshChannelRequestSubsystem _subsystem -> return False
    SshChannelRequestWindowChange winsize ->
      do liftIO (writeChan (sshChannelEvents channel) (SessionWinsize winsize))
         return True -- TODO: inform the callback

channelWrite :: Client -> SshState -> Word32 -> SshChannel -> Maybe S.ByteString -> IO ()
channelWrite client state channelId channel Nothing =
  send client state (SshMsgChannelClose (sshChannelRemote channel))

channelWrite client state channelId channel (Just msg)
  | S.null msg = return ()
  | otherwise =
     do sendSize <- atomically $
          do window <- readTVar (sshChannelWindowSize channel)
             when (window == 0) retry
             let sendSize = minimum [ sshChannelMaximumPacket channel
                                    , window
                                    , fromIntegral (S.length msg)
                                    ]
             writeTVar (sshChannelWindowSize channel) (window - sendSize)
             return (fromIntegral sendSize)
        let (current,next) = S.splitAt sendSize msg
        send client state (SshMsgChannelData (sshChannelRemote channel) current)
        channelWrite client state channelId channel (Just next)
