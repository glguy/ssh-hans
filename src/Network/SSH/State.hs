{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.SSH.State where


import           Network.SSH.Ciphers
import           Network.SSH.Keys
import           Network.SSH.Mac
import           Network.SSH.Messages
import           Network.SSH.Named
import           Network.SSH.Packet
import           Network.SSH.TerminalModes

import           Data.IORef
import           Data.Word
import           Data.Serialize.Get
import           Control.Concurrent
import           Data.ByteString.Short (ShortByteString)
import qualified Data.ByteString as S
import qualified Data.ByteString.Char8 as S8
import qualified Data.ByteString.Lazy as L
import           Crypto.Random


-- Server Internals ------------------------------------------------------------

data AuthResult
  = AuthFailed [ShortByteString]
  | AuthAccepted
  | AuthPkOk S.ByteString SshPubCert

data SessionEvent
  = SessionData S.ByteString
  | SessionClose
  | SessionWinsize SshWindowSize

data Client = Client
  -- | Read up to 'n' bytes from network socket
  { cGet         :: Int -> IO S.ByteString

  -- | Put bytes on network socket
  , cPut         :: L.ByteString -> IO ()

  -- | Close network socket
  , cClose       :: IO ()

  -- | TERM, initial window dimensions, termios flags, incoming events, write callback
  , cOpenShell   :: S.ByteString -> SshWindowSize -> [(TerminalFlag, Word32)] ->
                    Chan SessionEvent ->
                    (Maybe S.ByteString -> IO ()) ->
                    IO ()

  -- | ByteString argument is user name
  , cAuthHandler :: SshSessionId  ->
                    S.ByteString  ->
                    SshService    ->
                    SshAuthMethod ->
                    IO AuthResult
  }


data SshState = SshState
  { sshRecvState :: !(IORef (Word32, Cipher,Mac)) -- ^ Client context
  , sshBuf       :: !(IORef S.ByteString)
  , sshSendState :: !(MVar (Word32, Cipher, Mac, ChaChaDRG)) -- ^ Server encryption context
  , sshCookie    :: SshCookie
  }


initialState :: IO SshState
initialState  =
  do drg          <- drgNew
     sshRecvState <- newIORef (0,namedThing cipher_none nullKeys, namedThing mac_none ""    )
     sshSendState <- newMVar  (0,namedThing cipher_none nullKeys, namedThing mac_none "",drg)
     sshBuf       <- newIORef S.empty
     sshCookie    <- newCookie
     return SshState { .. }

-- | Construct a new, random cookie
newCookie :: IO SshCookie
newCookie = SshCookie `fmap` getRandomBytes 16

send :: Client -> SshState -> SshMsg -> IO ()
send client SshState { .. } msg =
  modifyMVar_ sshSendState $ \(seqNum, cipher, mac, gen) ->
    do let (pkt,cipher',gen') = putSshPacket seqNum cipher mac gen (putSshMsg msg)
       cPut client pkt
       return (seqNum+1, cipher',mac, gen')


receive :: Client -> SshState -> IO SshMsg
receive client SshState { .. } = loop
  where
  loop =
    do (seqNum, cipher, mac) <- readIORef sshRecvState
       (msg, cipher') <- parseFrom client sshBuf (getSshPacket seqNum cipher mac getSshMsg)
       writeIORef sshRecvState (seqNum+1, cipher', mac)
       case msg of
         SshMsgIgnore _                      -> loop
         SshMsgDebug display m _ | display   -> S8.putStrLn m >> loop -- XXX drop controls
                                 | otherwise -> loop
         _                                   -> return msg


parseFrom :: Client -> IORef S.ByteString -> Get a -> IO a
parseFrom handle buffer body =
  do bytes <- readIORef buffer
     go (runGetPartial body bytes)

  where
  -- boolean: beginning of packet
  go (Partial k) =
    do bytes <- cGet handle 32752
       go (k bytes)

  go (Done a bs) =
    do writeIORef buffer bs
       return a

  go (Fail s _) = fail s
